//go:build exclude_except_for_go_mod

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"example.org/private/selfbuild/golib"
)

const DEF_DNS_TIMEOUT = 4 * time.Second
const DEF_DNS_ATTEMPTS = 3
const MAX_DNS_ATTEMPTS = 6 // power-of-2 backoff, cumulative time ((2^this)-1)*timeout seconds (±10%)
const DEF_EDNS0_SIZE = 4096
const DEF_RESOLVERCONF = "/etc/resolv.conf"

var NotAnIPAddress = errors.New("not an IP address")

type DNSServFailErrT struct {
	ede string
}

func (e DNSServFailErrT) Error() string {
	if e.ede == "" {
		return "DNS SERVFAIL"
	}
	return "DNS SERVFAIL [" + e.ede + "]"
}

var opts struct {
	resolverConfigFile string
	qtype              string
	timeout            time.Duration
	dnsAttempts        uint
	edns0_size         uint
	skipLabels         uint
	askDomainParents   bool
	ipv4Transport      bool
	ipv6Transport      bool
	tcpTransport       bool
	ipReverse          bool
	checkPrimary       bool
	serialMode         bool
	showRRSIG          bool
	noNSID             bool
	addedServers       golib.AccumList
}

func registerFlags() {
	flag.StringVar(&opts.qtype, "t", "txt", "DNS query type")
	flag.StringVar(&opts.resolverConfigFile, "resolvconf", DEF_RESOLVERCONF, "DNS resolver config file")
	flag.DurationVar(&opts.timeout, "timeout", DEF_DNS_TIMEOUT, "DNS query timeout")
	flag.UintVar(&opts.dnsAttempts, "attempts", DEF_DNS_ATTEMPTS, "DNS max attempt count")
	flag.UintVar(&opts.edns0_size, "size", DEF_EDNS0_SIZE, "EDNS0 size")
	flag.UintVar(&opts.skipLabels, "skip-labels", 0, "skip N labels before trying to find NS")
	flag.BoolVar(&opts.askDomainParents, "ask-parents", false, "ask the servers for the public suffix domain")
	flag.BoolVar(&opts.ipv4Transport, "4", false, "Use IPv4 transport to DNS servers")
	flag.BoolVar(&opts.ipv6Transport, "6", false, "Use IPv6 transport to DNS servers")
	flag.BoolVar(&opts.tcpTransport, "tcp", false, "Use TCP transport to DNS servers")
	flag.BoolVar(&opts.ipReverse, "x", false, "If parameters are IP addresses, reverse into appropriate namespace")
	flag.BoolVar(&opts.checkPrimary, "primary", false, "Query to the SOA MNAME server too")
	flag.BoolVar(&opts.serialMode, "serial-mode", false, "Tune output for SOA Serial query mode")
	flag.BoolVar(&opts.showRRSIG, "show-rrsig", false, "Don't elide RRSIG RRs when showing response")
	flag.BoolVar(&opts.noNSID, "no-nsid", false, "Don't ask for NSID (in case of server bugs)")
	opts.addedServers.Validator = isIpAddress
	opts.addedServers.ResetOnDash = true
	flag.Var(&opts.addedServers, "servers", "Add to server list (or - to reset)")
	flag.Var(&opts.addedServers, "s", "Add to server list (or - to reset)")

}

func main() {
	registerFlags()
	golib.SetupFlags()
	flag.Parse()
	golib.HandleFlags()

	rrnames := flag.Args()
	if len(rrnames) == 0 {
		golib.Stderr("usage error: no rrnames to query; see -h")
		os.Exit(1)
	}
	if opts.dnsAttempts > MAX_DNS_ATTEMPTS {
		golib.Stderr("usage error: DNS attempt count %d > sane limit %d", opts.dnsAttempts, MAX_DNS_ATTEMPTS)
		os.Exit(1)
	}
	if opts.dnsAttempts < 1 {
		golib.Stderr("usage error: DNS attempt count %d less than 1", opts.dnsAttempts)
		os.Exit(1)
	}
	if opts.edns0_size > 0xFFFF {
		golib.Stderr("usage error: DNS size can not be greater than %d", 0xFFFF)
		os.Exit(1)
	}
	if opts.ipv4Transport && opts.ipv6Transport {
		golib.Stderr("usage error: use optional -4 or -6, not both")
		os.Exit(1)
	}
	if opts.addedServers.WasReset && len(opts.addedServers.L) == 0 {
		golib.Stderr("usage error: need to query a DNS server")
		os.Exit(1)
	}
	if opts.serialMode {
		opts.checkPrimary = true
		opts.qtype = "SOA"
	}

	idnaProfile := idna.New()

	succeeded := 0
	failed := 0
	resolvers := make([]*Domain, 0, len(rrnames))
	wg := &sync.WaitGroup{}

	for _, d := range rrnames {
		r, err := Resolver(d, opts.qtype, idnaProfile)
		if err != nil {
			golib.Stderr("Resolver creation (%q, %q) failed: %v", d, opts.qtype, err)
			failed += 1
			continue
		}
		wg.Add(1)
		go func() {
			r.Query()
			wg.Done()
		}()
		resolvers = append(resolvers, r)
	}
	wg.Wait()
	for i := range resolvers {
		resolvers[i].ShowEach(os.Stdout)
		if resolvers[i].Failed() {
			failed += 1
		} else {
			succeeded += 1
		}
	}
	fmt.Fprintf(os.Stderr, "; success: %d   failure: %d\n", succeeded, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

type QueryResult struct {
	Strings     []string
	NSID        string
	DurationQ   time.Duration
	DurationAll time.Duration
}

func NewQueryResult() *QueryResult      { return &QueryResult{Strings: make([]string, 0, 5)} }
func (qr *QueryResult) Add(item string) { qr.Strings = append(qr.Strings, item) }

type Domain struct {
	_            struct{}
	ctx          context.Context
	originalName string
	name         string
	qtypes       string
	idnaProfile  *idna.Profile

	qtype uint16

	// concurrent write access impossible, single thread populates this before we spin off multiples to check
	authNS []string

	// Might allow per-NS to append to this
	info []string

	// For the per-NS stage, protect concurrent access with a mutex
	sync.Mutex

	resultsPerNS map[string]*QueryResult

	// assumption: errors which are only in errors array are global, not tied
	// to a specific NS, and all errors per NS will be stored twice, once in
	// per-NS map and once in the top level.
	errorsPerNS map[string][]error
	errors      []error
}

type NotKnownQType string

func (nkq NotKnownQType) Error() string {
	return fmt.Sprintf("not a known qtype: %q", string(nkq))
}

type BadQueryName string

func (bqn BadQueryName) Error() string {
	if len(bqn) == 0 {
		return fmt.Sprintf("empty queries disallowed")
	}
	return fmt.Sprintf("invalid query name: %q\n", string(bqn))
}

func Resolver(domain, qtype string, idnaProfile *idna.Profile) (*Domain, error) {
	qt, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		return nil, NotKnownQType(qtype)
	}
	info := make([]string, 0, 10)

	reversed := false
	var sanitizedName string

	if opts.ipReverse {
		if arpa, err := dns.ReverseAddr(domain); err == nil {
			sanitizedName = arpa
			reversed = true
			info = append(info, fmt.Sprintf("reversed %q to %q", domain, sanitizedName))
		} else {
			info = append(info, fmt.Sprintf("could not reverse %q: %v", domain, err))
		}
	}

	if !reversed {
		// Memo to future self considering copy/paste: this, without the diagnostic
		// before the end, is covered by dns.CanonicalName()
		sanitizedName = strings.ToLower(domain)
		if len(sanitizedName) == 0 {
			return nil, BadQueryName("")
		}
		if sanitizedName != domain {
			info = append(info, fmt.Sprintf("normalized %q to %q", domain, sanitizedName))
		}
		if sanitizedName[len(sanitizedName)-1] != '.' {
			sanitizedName += "."
			// we stay diagnostic-silent about this change
		}

		if idnaProfile != nil {
			t, err := idnaProfile.ToASCII(sanitizedName)
			if err != nil {
				return nil, err
			}
			if t != sanitizedName {
				info = append(info, fmt.Sprintf("IDNA mapped %q to %q", sanitizedName, t))
				sanitizedName = t
			}
		}
	}

	d := Domain{
		originalName: domain,
		name:         sanitizedName,
		qtypes:       qtype,
		qtype:        qt,
		idnaProfile:  idnaProfile,
		ctx:          context.Background(),
		info:         info,
		authNS:       make([]string, 0, 14),
		resultsPerNS: make(map[string]*QueryResult, 10),
		errorsPerNS:  make(map[string][]error, 3),
		errors:       make([]error, 0, 20),
	}
	return &d, nil
}

func (d *Domain) Query() {
	d.findAuthNS()
	if len(d.errors) > 0 {
		return
	}
	d.queryEachAuth()
}

func (d *Domain) ShowEach(out io.Writer) {
	if len(d.authNS) == 0 {
		fmt.Fprintf(out, "; NO AUTH NAMESERVERS FOUND\n")
		for _, err := range d.errors {
			fmt.Fprintf(out, "; ERROR: %v\n", err)
		}
		return
	}
	for _, msg := range d.info {
		fmt.Fprintf(out, "; info: %s\n", msg)
	}
	if opts.serialMode {
		var (
			i, nLen, maxLen int
			ns              string
			msg             string
			sortedNS        []string
		)
		maxLen = 1
		sortedNS = make([]string, len(d.authNS))
		copy(sortedNS, d.authNS)
		for i = range d.authNS {
			nLen = len(d.authNS[i])
			if nLen > maxLen {
				maxLen = nLen
			}
		}
		sort.Strings(sortedNS) // FIXME: this should be a hostsort, not string lexicographic sort
		for i, ns = range sortedNS {
			if len(d.resultsPerNS[ns].Strings) != 1 {
				msg = fmt.Sprintf("[ERROR: got %d results]", len(d.resultsPerNS[ns].Strings))
			} else {
				// Ideally I'd still have access to the original response, but
				// this mode was bolted on later and the string form is what we
				// have.
				msg = strings.Fields(d.resultsPerNS[ns].Strings[0])[6]
			}
			fmt.Fprintf(out, "%-*s  %s\n", maxLen, ns, msg)
		}
		return
	}
	for _, ns := range d.authNS {
		qr, ok := d.resultsPerNS[ns]
		if ok && qr == nil {
			fmt.Fprintf(out, "; NAMESERVER: %q no results struct, internal bug?\n", ns)
		} else if ok {
			if opts.noNSID {
				fmt.Fprintf(out, "; NAMESERVER: %q [%v/%v]\n", ns, qr.DurationQ.Round(time.Millisecond), qr.DurationAll.Round(time.Millisecond))
			} else {
				fmt.Fprintf(out, "; NAMESERVER: %q (id: %q) [%v/%v]\n", ns, qr.NSID, qr.DurationQ.Round(time.Millisecond), qr.DurationAll.Round(time.Millisecond))
			}
			for _, msg := range qr.Strings {
				fmt.Fprintf(out, "%s\n", msg)
			}
		} else {
			fmt.Fprintf(out, "; NAMESERVER: %q no results map entry, internal bug?\n", ns)
		}
		for _, err := range d.errorsPerNS[ns] {
			fmt.Fprintf(out, "; ERROR: %v\n", err)
		}
		fmt.Fprintf(out, "\n")
	}
}

func (d *Domain) Failed() bool {
	return len(d.errors) > 0
}

func (d *Domain) findAuthNS() {
	var (
		nsList          NSList
		err, err2       error
		offset          int
		end             bool
		skipped         uint
		primaryCapacity int
		foundPrimary    string
		startTime       time.Time
		resDuration     time.Duration
		registeredDom   string
	)
	qname := d.name
	if opts.addedServers.WasReset {
		qname = ""
	}
	startTime = time.Now()
	for len(qname) > 0 {

		// This is equivalent to an auto-derived skipLabels; we put it first so
		// that the two can be used together, in case there's a multi-level
		// public suffix domain (other than TLD).
		if opts.askDomainParents {
			t, _ := publicsuffix.PublicSuffix(qname[:len(qname)-1])
			if t == "" {
				d.errors = append(d.errors, fmt.Errorf("failed to find public suffix of %q", qname))
				break
			}
			qname = t + "."
		}

		// This helps with wanting to query NS type at parent, for glue
		if opts.skipLabels > 0 {
			if skipped < opts.skipLabels {
				skipped += 1
				offset, end = dns.NextLabel(d.name, offset)
				if end {
					d.errors = append(d.errors, fmt.Errorf("skipped all %d labels of qname %q", skipped, d.name))
					break
				}
				qname = d.name[offset:]
				continue
			}
		}

		// This diagnostic, uncommented, shows the NextLabel splitting working:
		//d.info = append(d.info, fmt.Sprintf("querying for NS of: %q", qname))
		nsList, err = LookupNS(d.ctx, qname)
		if err == nil {
			resDuration = time.Since(startTime).Round(time.Millisecond)
			suf := "s"
			l := nsList.Length()
			if l == 1 {
				suf = ""
			}
			d.info = append(d.info, fmt.Sprintf("found %d NS record%s for %q in %s", l, suf, qname, resDuration))
			break
		} else if servFail, ok := err.(DNSServFailErrT); ok {
			if registeredDom == "" {
				registeredDom, err2 = publicsuffix.EffectiveTLDPlusOne(qname[:len(qname)-1]) // get empty result if trailing dot included
				if err2 != nil {
					d.errors = append(d.errors, fmt.Errorf("unable to derive publicsuffix-based domain of %q: %w", qname, err2))
				} else {
					registeredDom += "."
				}
			}
			// We've sanitized to lower-case, I think the PSL stuff will always be lower-case
			if qname == registeredDom {
				d.errors = append(d.errors, fmt.Errorf("%s on public-registered domain %q, not asking TLDish servers", servFail, qname))
				return
			} else {
				d.info = append(d.info, fmt.Sprintf("lookup %q NS got %s, something is broken (on their side?)", qname, servFail))
			}
		}

		// dns.NextLabel handles backslash escapes
		offset, end = dns.NextLabel(d.name, offset)
		if end {
			break
		}
		qname = d.name[offset:]
	}
	if err != nil {
		d.errors = append(d.errors, err)
		return
	}
	if opts.checkPrimary {
		soaResults, err := recursiveResolve(d.ctx, qname, dns.TypeSOA)
		if err == nil && len(soaResults) == 1 {
			soa := soaResults[0].(*dns.SOA)
			if soa.Ns != "" {
				foundPrimary = soa.Ns
				primaryCapacity = 1
			}
		}
	}
	d.authNS = make([]string, nsList.Length()+len(opts.addedServers.L)+primaryCapacity)
	for i := 0; i < nsList.Length(); i++ {
		d.authNS[i] = nsList.HostAt(i)
	}
	if len(opts.addedServers.L) > 0 {
		base := nsList.Length()
		for i := range opts.addedServers.L {
			d.authNS[base+i] = opts.addedServers.L[i]
		}
	}
	if opts.checkPrimary && foundPrimary != "" {
		for i := range d.authNS {
			if d.authNS[i] == foundPrimary {
				primaryCapacity = 0
				break
			}
		}
		if primaryCapacity > 0 {
			d.info = append(d.info, fmt.Sprintf("found distinct SOA MName for %q", qname))
			d.authNS[nsList.Length()+len(opts.addedServers.L)] = foundPrimary
		} else {
			// Slice [x:y] is x thru y-1 inclusive, so :len(slice) gets the
			// entire thing; so if the primary is already present we're
			// removing just one from the length to remove the mistakenly
			// extended length.
			d.info = append(d.info, fmt.Sprintf("found SOA MName already in NS for %q", qname))
			d.authNS = d.authNS[:len(d.authNS)-1]
		}
	}
}

type NSList struct {
	hosts []string
}

func (nl NSList) Length() int             { return len(nl.hosts) }
func (nl NSList) HostAt(index int) string { return nl.hosts[index] }

func LookupNS(ctx context.Context, name string) (NSList, error) {
	nsResults, err := recursiveResolve(ctx, name, dns.TypeNS)
	if err != nil {
		return NSList{}, err
	}
	if len(nsResults) == 0 {
		return NSList{}, errors.New("no NS results")
	}
	hosts := make([]string, len(nsResults))
	for i := range nsResults {
		ns, ok := nsResults[i].(*dns.NS)
		if !ok {
			panic("programming bug: non-NS result returned from recursiveResolve")
		}
		hosts[i] = ns.Ns
	}
	return NSList{hosts: hosts}, nil
}

func recursiveResolve(ctx context.Context, qDomain string, qType uint16) ([]dns.RR, error) {
	// This is currently naive and does not handle fallback to secondary resolvers with decent concurrency.
	client := dns.Client{
		Timeout: opts.timeout,
		Net:     networkPerOptions(),
	}
	m := &dns.Msg{}
	m.RecursionDesired = true
	m = m.SetQuestion(qDomain, qType)
	m = m.SetEdns0(uint16(opts.edns0_size), true)
	var (
		cfg         *dns.ClientConfig
		err         error
		firstError  error
		netError    net.Error
		msg         *dns.Msg
		i           uint
		serverIndex int
		server      string
	)
	cfg, err = loadDNSClientConfig()
	if err != nil {
		return nil, err
	}
	for i = 0; i < opts.dnsAttempts; i++ {
		if i > 0 {
			time.Sleep(retryJitter((2 << (i - 1)) * time.Second))
		}
		// TODO: implement concurrency and raise serverIndex (% len(cfg.Servers))
		server = cfg.Servers[serverIndex] + ":" + cfg.Port
		msg, _, err = client.ExchangeContext(ctx, m, server)
		if err != nil {
			if i == 0 {
				firstError = err
			}
			if errors.As(err, &netError) && netError.Timeout() {
				continue
			}
		}
		break
	}
	if err != nil {
		return nil, firstError
	}
	if msg.Rcode == dns.RcodeServerFailure {
		if ede, ok := extractExtendedError(msg); ok {
			return nil, DNSServFailErrT{ede: ede}
		}
		return nil, DNSServFailErrT{}
	}
	sought := make([]dns.RR, 0, len(msg.Answer))
	for i := range msg.Answer {
		if msg.Answer[i].Header().Rrtype != qType {
			continue // CNAME, RRSIG, etc
		}
		sought = append(sought, msg.Answer[i])
	}
	return sought, nil
}

func (d *Domain) queryEachAuth() {
	wg := &sync.WaitGroup{}
	wg.Add(len(d.authNS))
	for _, ns := range d.authNS {
		go func(ns string) {
			d.queryOneNS(ns)
			wg.Done()
		}(ns)
	}
	wg.Wait()
}

// called under concurrency, must lock Domain before updating maps/hashes
func (d *Domain) queryOneNS(ns string) {
	client := dns.Client{
		Timeout: opts.timeout,
		Net:     networkPerOptions(),
	}
	m := &dns.Msg{}
	m = m.SetQuestion(d.name, d.qtype)
	if opts.noNSID {
		m = m.SetEdns0(uint16(opts.edns0_size), true)
	} else {
		// See .SetEdns0 implementation
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(uint16(opts.edns0_size))
		o.SetDo()
		oNSID := new(dns.EDNS0_NSID)
		oNSID.Code = dns.EDNS0NSID
		o.Option = append(o.Option, oNSID)
		m.Extra = append(m.Extra, o)
	}
	var (
		err        error
		firstError error
		netError   net.Error
		msg        *dns.Msg
		i          uint
		allStart   time.Time
		thisStart  time.Time
	)
	qr := NewQueryResult()
	allStart = time.Now()
	for i = 0; i < opts.dnsAttempts; i++ {
		if i > 0 {
			time.Sleep(retryJitter((2 << (i - 1)) * time.Second))
		}
		thisStart = time.Now()
		msg, _, err = client.ExchangeContext(d.ctx, m, ns+":53")
		qr.DurationQ = time.Since(thisStart)
		if err != nil {
			if i == 0 {
				firstError = err
			}
			if errors.As(err, &netError) && netError.Timeout() {
				continue
			}
		}
		break
	}
	qr.DurationAll = time.Since(allStart)
	// skip the duration rtt
	d.Lock()
	defer d.Unlock()
	if err != nil {
		d.errors = append(d.errors, firstError)
		d.errorsPerNS[ns] = append(d.errorsPerNS[ns], firstError)
		return
	}
	for i := range msg.Answer {
		suffix := ""
		if h := msg.Answer[i].Header(); h != nil {
			switch h.Rrtype {
			case dns.TypeDNSKEY:
				dk := msg.Answer[i].(*dns.DNSKEY)
				suffix += "\t;"
				if dk.Flags&dns.SEP != 0 {
					suffix += " [SEP]"
				}
				if dk.Flags&dns.REVOKE != 0 {
					suffix += " [REVOKE]"
				}
				if dk.Flags&dns.ZONE != 0 {
					suffix += " [ZONE]"
				}
				ds := dk.ToDS(dns.SHA256)
				suffix += fmt.Sprintf(" | DS keytag=%d alg=%d digesttype=%d digest=%s",
					ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
			case dns.TypeRRSIG:
				if !opts.showRRSIG {
					continue
				}
			}
		}
		qr.Add(msg.Answer[i].String() + suffix)
	}
	if len(msg.Answer) == 0 {
		if msg.Truncated {
			d.errorsPerNS[ns] = append(d.errorsPerNS[ns], fmt.Errorf("truncated: %s", ns))
		} else {
			qr.Add("; no results, " + dns.RcodeToString[msg.Rcode])
			if ede, ok := extractExtendedError(msg); ok {
				qr.Add("; extended error: " + ede)
			}
		}
	} else if msg.Truncated {
		qr.Add("; ... truncated ...")
	}

	if d.qtype == dns.TypeNS && len(msg.Answer) == 0 && len(msg.Ns) > 0 {
		// We will return glue of NS from authority section
		// Note that DS records are authoritative in parent so should have been in the answer section.
		qr.Add("; from the Authority/NS section:")
		for i := range msg.Ns {
			h := msg.Ns[i].Header()
			if h == nil {
				continue
			}
			if h.Rrtype != dns.TypeNS {
				continue
			}
			qr.Add(msg.Ns[i].String())
		}
	}

	if !opts.noNSID {
		responseOpts := extractOpt(msg)
		if responseOpts != nil {
			for _, o := range responseOpts.Option {
				switch realO := o.(type) {
				case *dns.EDNS0_NSID:
					// RFC 5001 insist that you must always use hex.
					// So the DNS lib has helpfully converted to hex for us.
					// Yet normally, there's a convenient human string in there.
					qr.NSID = nsidRender(realO)
				}
			}
		}
	}

	// FIXME: prior result?
	d.resultsPerNS[ns] = qr
}

func retryJitter(base time.Duration) time.Duration {
	b := float64(base)
	offsetFactor := rand.Float64()*0.2 - 0.1 // ±10%
	return time.Duration(b + offsetFactor*b)
}

func networkPerOptions() string {
	if opts.tcpTransport {
		if opts.ipv4Transport {
			return "tcp4"
		}
		if opts.ipv6Transport {
			return "tcp6"
		}
		return "tcp"
	}
	if opts.ipv4Transport {
		return "udp4"
	}
	if opts.ipv6Transport {
		return "udp6"
	}
	return "udp"
}

func isIpAddress(candidate string) error {
	t := net.ParseIP(candidate)
	if t == nil {
		return NotAnIPAddress
	}
	return nil
}

var (
	loadedResolverCfg *dns.ClientConfig
	loadedResolverErr error
	loadResolverOnce  sync.Once
)

func loadDNSClientConfig() (*dns.ClientConfig, error) {
	loadResolverOnce.Do(func() {
		loadedResolverCfg, loadedResolverErr = dns.ClientConfigFromFile(opts.resolverConfigFile)
	})
	return loadedResolverCfg, loadedResolverErr
}

func extractOpt(msg *dns.Msg) (opt *dns.OPT) {
	if len(msg.Extra) == 0 {
		return nil
	}
	last := msg.Extra[len(msg.Extra)-1]
	if last.Header().Rrtype != dns.TypeTSIG && len(msg.Extra) >= 2 {
		last = msg.Extra[len(msg.Extra)-2]
	}
	if last.Header().Rrtype != dns.TypeOPT {
		return nil
	}
	opt, ok := last.(*dns.OPT)
	if !ok {
		panic("rr of type OPT does not typecast to dns.Opt")
	}
	return opt
}

func extractExtendedError(msg *dns.Msg) (ede string, ok bool) {
	opt := extractOpt(msg)
	if opt == nil {
		return "", false
	}
	for _, o := range opt.Option {
		switch o.(type) {
		case *dns.EDNS0_EDE:
			return o.String(), true
		}
	}
	return "", false
}

func nsidRender(opt *dns.EDNS0_NSID) string {
	// The RFC 5001 approach: return opt.String()
	// So, we're going to have to hex-decode the freshly hex-encoded string for us, because the dns lib hides the raw bytes
	h, err := hex.DecodeString(opt.Nsid)
	if err != nil {
		return opt.String() + "<" + err.Error() + ">"
	}
	safe := true
	for i := range h {
		if h[i] >= 0x7F || !unicode.IsPrint(rune(h[i])) {
			safe = false
			break
		}
	}
	if safe {
		return string(h)
	}
	return opt.Nsid
}
