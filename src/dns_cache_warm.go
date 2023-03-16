//go:build exclude_except_for_go_mod

// NEXT SHOULD COME: GRID RESULTS (sanity) (back-channel from per-resolver to admin)

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/mitchellh/go-homedir"

	"example.org/private/selfbuild/golib"
)

const CONCURRENT = 20
const EST_MAX_QUERIES = 2000 // we make a bunch of channels of this size
const CONFIG_FILE_DEFAULT = "~/etc/dns-cache-warm.conf"
const ENVVAR_EXTRA_RESOLVE = "DNS_CACHE_EXTRA_RESOLVE"
const EDNS0_SIZE = 4096
const DNSSEC_DO = true
const DNS_RETRY_COUNT = 3
const DNS_RETRY_INITIAL_BACKOFF = time.Second
const DNS_RETRY_BACKOFF_FACTOR = 2 // needs to be int
// RFC1536 notes as a good implementation that Bind "starts with a time-out
// equal to the greater of 4 seconds and two times the round-trip time estimate
// of the server.  The time-out is backed off with each cycle, exponentially,
// to a ceiling value of 45 seconds."
//
// miekg/dns timeouts default to 2s.
const DNS_TIMEOUT = 4 * time.Second

type ResolveType uint

const (
	ResHost ResolveType = iota + 1
	ResA
	ResAAAA
	ResMX
	ResSRV
	ResPTR
	ResTXT
	ResXAPtr
	ResXAAAAPtr
	ResXPtr
)

type ResolveWrapper struct {
	Queue chan<- Item
	wg    *sync.WaitGroup
	hosts []string
	stats Stats
}

type Item struct {
	restype ResolveType
	rrname  string
}

type RecClient struct {
	client dns.Client
	label  string
	target string
}

type Stats struct {
	serverCount        uint32
	configRequestCount uint32
	queryCount         int64 // for sanity, I add but sometimes subtract one
	rrCount            uint64
	retryCount         uint32
	failedCount        uint32
	timedoutCount      uint32
	unhandledCount     uint32
	noresultsCount     uint32
	startTime          time.Time
	durations          sync.Map
}

func startResolver(resolverHosts []string) (rw *ResolveWrapper, err error) {
	err = nil
	frontCh := make(chan Item)
	ch := make(chan Item)
	rw = &ResolveWrapper{
		Queue: frontCh,
		wg:    &sync.WaitGroup{},
		hosts: resolverHosts,
		stats: Stats{
			startTime: time.Now(),
		},
	}
	rw.wg.Add(2)
	go rw.countRequests(frontCh, ch)
	if len(rw.hosts) == 0 {
		for i := 0; i < CONCURRENT; i++ {
			rw.wg.Add(1)
			go oneResolverStdlib(i, ch, rw.wg, &rw.stats)
		}
	} else {
		var resolverCount = len(rw.hosts)
		atomic.AddUint32(&rw.stats.serverCount, uint32(resolverCount))
		rw.wg.Add((1 + resolverCount) * CONCURRENT)
		for i := 0; i < CONCURRENT; i++ {
			prRChans := make([]<-chan Item, resolverCount)
			prWChans := make([]chan<- Item, resolverCount)
			for j := 0; j < resolverCount; j++ {
				// We buffer this so that adding new queries isn't locked on
				// the slowest of the resolvers we talk to, thus inadvertently
				// aligning total duration to the sum of the slowest for each
				// name, rather than the max of the slowest resolver.
				n := make(chan Item, EST_MAX_QUERIES)
				prWChans[j] = n
				prRChans[j] = n
				go oneResolverPerTarget(j+resolverCount*i, prRChans[j], rw.wg, rw.hosts[j], &rw.stats)
			}
			go adminResolver(i, ch, prWChans, rw.wg)
		}
	}
	return rw, nil
}

func (rw *ResolveWrapper) countRequests(frontCh <-chan Item, backCh chan<- Item) {
	defer rw.wg.Done()
	for {
		item, ok := <-frontCh
		if !ok {
			close(backCh)
			break
		}
		atomic.AddUint32(&rw.stats.configRequestCount, 1)
		backCh <- item
	}
}

func (rw *ResolveWrapper) Finish() {
	close(rw.Queue)
	rw.wg.Done()
}

func (rw *ResolveWrapper) Wait() {
	rw.wg.Wait()
}

func oneResolverStdlib(index int, ch <-chan Item, wg *sync.WaitGroup, stats *Stats) {
	defer wg.Done()
	start := time.Now()
	res := &net.Resolver{}
	for {
		item, ok := <-ch
		if !ok {
			break
		}
		resolveStdlib(index, res, item, stats)
	}
	stats.durations.Store("stdlib", time.Now().Sub(start))
}

func adminResolver(index int, inbound <-chan Item, chList []chan<- Item, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		for i := 0; i < len(chList); i++ {
			close(chList[i])
		}
	}()
	for {
		item, ok := <-inbound
		if !ok {
			break
		}
		for i := 0; i < len(chList); i++ {
			chList[i] <- item
		}
	}
}

func oneResolverPerTarget(resIndex int, ch <-chan Item, wg *sync.WaitGroup, resolverName string, stats *Stats) {
	defer wg.Done()
	start := time.Now()
	rc := &RecClient{
		client: dns.Client{
			Timeout: DNS_TIMEOUT,
		},
		label:  resolverName,
		target: resolverName + ":53",
	}
	for {
		item, ok := <-ch
		if !ok {
			break
		}
		resolvePerTarget(resIndex, rc, item, stats)
	}
	stats.durations.Store(resolverName, time.Now().Sub(start))
}

func resolveStdlib(index int, res *net.Resolver, item Item, stats *Stats) {
	ctx := context.Background()
	atomic.AddInt64(&stats.queryCount, 1)
	switch item.restype {
	// FIXME: ResA != ResHost -- blocked on use different resolver
	case ResHost, ResA, ResAAAA:
		if strings.HasPrefix(item.rrname, "*.") {
			// blocked on use different resolver
			atomic.AddInt64(&stats.queryCount, -1)
			atomic.AddUint32(&stats.unhandledCount, 1)
			failuref("resolver[%d] FIXME: wildcards unsupported in LookupHost(%q)", index, item.rrname)
			return
		}
		hostList, err := res.LookupHost(ctx, item.rrname)
		if err != nil {
			atomic.AddUint32(&stats.failedCount, 1)
			failuref("resolver[%d] LookupHost(%q) failed: %v", index, item.rrname, err)
			return
		}
		repr := strings.Join(hostList, ", ")
		resultf("[%d]: host(%q): %s", index, item.rrname, repr)
	case ResMX:
		mxList, err := res.LookupMX(ctx, item.rrname)
		if err != nil {
			atomic.AddUint32(&stats.failedCount, 1)
			failuref("resolver[%d] LookupMX(%q) failed: %v", index, item.rrname, err)
			return
		}
		mxRepr := make([]string, len(mxList))
		for i := 0; i < len(mxList); i++ {
			mxRepr[i] = strconv.Itoa(int(mxList[i].Pref)) + " " + strconv.QuoteToASCII(mxList[i].Host)
		}
		repr := strings.Join(mxRepr, ", ")
		resultf("[%d]: MX(%q): %v", index, item.rrname, repr)
	case ResSRV:
		parts := strings.SplitN(item.rrname, ".", 3)
		if len(parts[0]) < 2 || len(parts[1]) < 2 || len(parts[2]) < 1 || parts[0][0] != '_' || parts[1][0] != '_' {
			atomic.AddInt64(&stats.queryCount, -1)
			atomic.AddUint32(&stats.unhandledCount, 1)
			failuref("resolver[%d] MALFORMED SRV: %q", index, item.rrname)
			return
		}
		_, srvList, err := res.LookupSRV(ctx, "", "", item.rrname)
		if err != nil {
			atomic.AddUint32(&stats.failedCount, 1)
			failuref("resolver[%d] LookupSRV(%q) failed: %v", index, parts[2], err)
			return
		}
		srvRepr := make([]string, len(srvList))
		for i := 0; i < len(srvList); i++ {
			srvRepr[i] = fmt.Sprintf("%d %d %d %q", srvList[i].Priority, srvList[i].Weight, srvList[i].Port, srvList[i].Target)
		}
		repr := strings.Join(srvRepr, ", ")
		resultf("[%d]: SRV(%q): %v", index, item.rrname, repr)
	case ResPTR:
		atomic.AddInt64(&stats.queryCount, -1)
		atomic.AddUint32(&stats.unhandledCount, 1)
		failuref("resolver[%d] UNHANDLED PTR for %q", index, item.rrname)
	case ResTXT:
		txtList, err := res.LookupTXT(ctx, item.rrname)
		if err != nil {
			atomic.AddUint32(&stats.failedCount, 1)
			failuref("resolver[%d] LookupTXT(%q) failed: %v", index, item.rrname, err)
			return
		}
		txtRepr := make([]string, len(txtList))
		for i := 0; i < len(txtList); i++ {
			txtRepr[i] = strconv.QuoteToASCII(txtList[i])
		}
		repr := strings.Join(txtRepr, ", ")
		resultf("[%d]: TXT(%q): %v", index, item.rrname, repr)
	case ResXPtr:
		atomic.AddInt64(&stats.queryCount, -1)
		atomic.AddUint32(&stats.unhandledCount, 1)
		failuref("resolver[%d] UNHANDLED X:PTR for %q", index, item.rrname)
	case ResXAPtr, ResXAAAAPtr:
		var qnet string
		if item.restype == ResXAPtr {
			qnet = "ip4"
		} else {
			qnet = "ip6"
		}
		ipList, err := res.LookupIP(ctx, qnet, item.rrname)
		if err != nil {
			atomic.AddUint32(&stats.failedCount, 1)
			failuref("resolver[%d] LookipIP(%s, %q) failed: %v", index, qnet, item.rrname, err)
			return
		}
		// blocked on use different resolver
		atomic.AddUint32(&stats.unhandledCount, 1)
		failuref("[%d] FIXME: %s/PTR lookups UNIMPLEMENTED [%q got %d results]", index, qnet, item.rrname, len(ipList))
	default:
		atomic.AddInt64(&stats.queryCount, -1)
		failuref("resolver[%d] unknown restype %d for %q", index, item.restype, item.rrname)
	}
}

func resolvePerTarget(resIndex int, rc *RecClient, item Item, stats *Stats) {
	ctx := context.Background()
	shouldQualify := true
	m := dns.Msg{}
	var (
		qrtype   uint16
		qrtLabel string
		followUp bool
		err      error
	)
	qualRRName := item.rrname
	switch item.restype {
	// ResHost really should do AAAA and MX too, but FIXME for now just do A
	case ResHost, ResA:
		qrtype, qrtLabel = dns.TypeA, "A"
	case ResAAAA:
		qrtype, qrtLabel = dns.TypeAAAA, "AAAA"
	case ResMX:
		qrtype, qrtLabel = dns.TypeMX, "MX"
	case ResSRV:
		qrtype, qrtLabel = dns.TypeSRV, "SRV"
	case ResPTR:
		qrtype, qrtLabel = dns.TypePTR, "PTR"
	case ResTXT:
		qrtype, qrtLabel = dns.TypeTXT, "TXT"
	case ResXPtr:
		qrtype, qrtLabel = dns.TypePTR, "PTR"
		qualRRName, err = dns.ReverseAddr(qualRRName)
		if err != nil {
			atomic.AddUint32(&stats.unhandledCount, 1)
			failuref("[%d: %q]: query %q reversing address failed: %v", resIndex, rc.label, qualRRName, err)
			return
		}
		shouldQualify = false
	case ResXAPtr:
		qrtype, qrtLabel = dns.TypeA, "A(*)"
		followUp = true
	case ResXAAAAPtr:
		qrtype, qrtLabel = dns.TypeAAAA, "AAAA(*)"
		followUp = true
	default:
		atomic.AddUint32(&stats.unhandledCount, 1)
		failuref("CODE BUG: unhandled item.restype %v for %q", item.restype, item.rrname)
	}

	if shouldQualify && !strings.HasSuffix(qualRRName, ".") {
		qualRRName += "."
	}

	m.SetQuestion(qualRRName, qrtype)
	if DNSSEC_DO {
		m.SetEdns0(EDNS0_SIZE, DNSSEC_DO)
	}

	var (
		r   *dns.Msg
		max int
	)
	for retry, backoff := 0, DNS_RETRY_INITIAL_BACKOFF; ; retry++ {
		if retry > 0 {
			if retry > DNS_RETRY_COUNT {
				failuref("[%d: %q]: retry limit exceeded", resIndex, rc.label)
				return
			}
			time.Sleep(retryJitter(backoff))
			backoff *= DNS_RETRY_BACKOFF_FACTOR
			atomic.AddUint32(&stats.retryCount, 1)
		}

		// FIXME: no context use really
		// FIXME: no retry handling for DNS timeouts, with exponential capped backoff up to N queries
		// FIXME: this is very little more than fire-and-forget with optimistic reporting
		atomic.AddInt64(&stats.queryCount, 1)
		r, _, err = rc.client.ExchangeContext(ctx, &m, rc.target)
		if err != nil {
			resultf("[%d: %q]: query %q/%s failed: %v", resIndex, rc.label, qualRRName, qrtLabel, err)
			if err, ok := err.(net.Error); ok && err.Timeout() {
				atomic.AddUint32(&stats.timedoutCount, 1)
				continue
			} else {
				atomic.AddUint32(&stats.failedCount, 1)
				return
			}
		}
		if len(r.Answer) == 0 {
			atomic.AddUint32(&stats.noresultsCount, 1)
			resultf("[%d: %q]: query %q/%s returned NO RESULTS", resIndex, rc.label, qualRRName, qrtLabel)
			return
		}
		max = len(r.Answer)
		for i := range r.Answer {
			atomic.AddUint64(&stats.rrCount, 1)
			resultf("[%d: %q]: %q/%s → %d/%d: %s", resIndex, rc.label, qualRRName, qrtLabel, i+1, max, r.Answer[i].String())
			// FIXME: if CNAME or qrtype, then print, else flag up for attention
		}
		break
	}

	if !followUp {
		return
	}

	// FIXME: do reverse queries
	for i := range r.Answer {
		switch r.Answer[i].Header().Rrtype {
		case qrtype:
			// great!
		case dns.TypeCNAME, dns.TypeRRSIG:
			continue
		default:
			failuref("*** %q %d/%d : EXPECTED %s GOT %q ***", qualRRName, i+1, max, qrtLabel, r.Answer[i].String())
			continue
		}

		var (
			ip   string
			arpa string
			err  error
		)
		switch qrtype {
		case dns.TypeA:
			aRecord := r.Answer[i].(*dns.A)
			ip = aRecord.A.String()
		case dns.TypeAAAA:
			aaaaRecord := r.Answer[i].(*dns.AAAA)
			ip = aaaaRecord.AAAA.String()
		default:
			failuref("reverse: unexpected qrtype %v (%q)", qrtype, qrtLabel)
		}
		arpa, err = dns.ReverseAddr(ip)
		if err != nil {
			atomic.AddUint32(&stats.unhandledCount, 1)
			failuref("*** %q %d/%d : reverse(%q) failed: %v", qualRRName, i+1, max, ip, err)
			continue
		}
		resultf("*** %q %d/%d : %q ***", qualRRName, i+1, max, arpa)
		resolvePerTarget(resIndex, rc, Item{ResPTR, arpa}, stats)
	}
}

func streamFromConfig(fn string) (<-chan Item, error) {
	ch := make(chan Item)
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	go parseConfigBufferToChan(f, ch)
	return ch, nil
}

func streamFromString(dataStr string) <-chan Item {
	ch := make(chan Item)
	rdr := io.NopCloser(strings.NewReader(dataStr))
	go parseConfigBufferToChan(rdr, ch)
	return ch
}

func parseLine(num int, text string) (Item, bool) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return Item{}, false
	}
	if len(fields) != 2 {
		failuref("config line %d: wrong field count %d (%q)", num, len(fields), text)
		return Item{}, false
	}
	switch c := strings.ToLower(fields[0]); c {
	case "host":
		return Item{ResHost, fields[1]}, true
	case "a":
		return Item{ResA, fields[1]}, true
	case "aaaa":
		return Item{ResAAAA, fields[1]}, true
	case "mx":
		return Item{ResMX, fields[1]}, true
	case "srv":
		return Item{ResSRV, fields[1]}, true
	case "ptr":
		return Item{ResPTR, fields[1]}, true
	case "txt":
		return Item{ResTXT, fields[1]}, true
	case "x:ptr":
		return Item{ResXPtr, fields[1]}, true
	case "x:a:ptr":
		return Item{ResXAPtr, fields[1]}, true
	case "x:aaaa:ptr":
		return Item{ResXAAAAPtr, fields[1]}, true
	default:
		failuref("config line %d: unknown directive %q", num, c)
		return Item{}, false
	}
}

func parseConfigBufferToChan(r io.ReadCloser, ch chan<- Item) {
	defer r.Close()
	defer close(ch)
	b := bufio.NewReader(r)
	lineno := 0
	for {
		t, err := b.ReadString('\n')
		if err != nil && err != io.EOF {
			break
		}
		lineno++
		if strings.HasPrefix(t, "#") {
			continue
		}
		if i, ok := parseLine(lineno, t); ok {
			ch <- i
		}
		if err != nil {
			break
		}
	}
}

func retryJitter(base time.Duration) time.Duration {
	// Lifted from my ocsprenewer logic ... and in review, bug spotted and ported back
	b := float64(base)
	// 10% +/-
	offsetFactor := rand.Float64()*0.2 - 0.1
	return time.Duration(b + offsetFactor*b)
}

func (rw *ResolveWrapper) PrintSummary() {
	endTime := time.Now()
	duration := endTime.Sub(rw.stats.startTime).Round(time.Millisecond)

	requested := atomic.LoadUint32(&rw.stats.configRequestCount)
	servers := atomic.LoadUint32(&rw.stats.serverCount)
	queries := atomic.LoadInt64(&rw.stats.queryCount)
	retries := atomic.LoadUint32(&rw.stats.retryCount)
	timeouts := atomic.LoadUint32(&rw.stats.timedoutCount)
	failed := atomic.LoadUint32(&rw.stats.failedCount)
	unhandled := atomic.LoadUint32(&rw.stats.unhandledCount)
	noresults := atomic.LoadUint32(&rw.stats.noresultsCount)
	rrs := atomic.LoadUint64(&rw.stats.rrCount)

	var targetRepr, statsRepr string
	if servers > 0 {
		targetRepr = fmt.Sprintf("to each of %d servers", servers)
		statsRepr = fmt.Sprintf(", with %d RRs returned; %d retries %d timeouts %d failures %d unhandled %d no-results",
			rrs, retries, timeouts, failed, unhandled, noresults,
		)
	} else {
		targetRepr = "via stdlib"
	}

	log.Printf("Summary: %v for %d requests %s, taking %d queries%s",
		duration, requested, targetRepr,
		queries, statsRepr)

	// We actually time always, it's simpler than making the time conditional
	// and the overhead is low.  So really it's "report that we timed".
	if opts.TimeResolvers {
		// it's servers else 1, Go has no ternary, just add 1
		names := make([]string, 0, servers+1)
		durations := make(map[string]time.Duration, servers+1)
		rw.stats.durations.Range(func(i, v interface{}) bool {
			n := i.(string)
			d := v.(time.Duration)
			names = append(names, n)
			durations[n] = d
			return true
		})
		sort.Strings(names) // do I have a convenient IPsort/HOSTsort around?
		for _, name := range names {
			log.Printf(" [%7.3fs] %s", durations[name].Seconds(), name)
		}
	}
}

var opts struct {
	ProgressOnly  bool
	TimeResolvers bool
	ConfigFile    string
}

type progressT struct {
	count uint32
}

var progress progressT

func (p *progressT) Add() uint32 { return atomic.AddUint32(&p.count, 1) }
func (p *progressT) VisibleAdd() {
	fmt.Printf("%s: %d \r", golib.Progname, p.Add())
}

func registerFlags() {
	defaultConfig, err := homedir.Expand(CONFIG_FILE_DEFAULT)
	if err != nil {
		log.Fatal("homedir.Expand", err)
	}

	flag.BoolVar(&opts.ProgressOnly, "progress", false, "show progress & summary only")
	flag.BoolVar(&opts.ProgressOnly, "p", false, "show progress & summary only")
	flag.BoolVar(&opts.TimeResolvers, "time-resolvers", false, "show summary times per resolver")
	flag.StringVar(&opts.ConfigFile, "config", defaultConfig, "file with DNS entries to resolve")
}

func failuref(template string, args ...interface{}) {
	log.Printf(template, args...)
}

func resultf(template string, args ...interface{}) {
	if opts.ProgressOnly {
		progress.VisibleAdd()
		return
	}
	progress.Add()
	log.Printf(template, args...)
}

func main() {
	registerFlags()
	golib.FastFlags()
	log.SetFlags(0)

	resolve, err := startResolver(flag.Args())
	if err != nil {
		log.Fatal("startResolver", err)
	}

	items, err := streamFromConfig(opts.ConfigFile)
	if err != nil {
		log.Fatal("stream from config", err)
	}

	for item := range items {
		resolve.Queue <- item
	}

	if envVal, ok := os.LookupEnv(ENVVAR_EXTRA_RESOLVE); ok {
		for item := range streamFromString(envVal) {
			resolve.Queue <- item
		}
	}

	resolve.Finish()

	resolve.Wait()

	resolve.PrintSummary()
}
