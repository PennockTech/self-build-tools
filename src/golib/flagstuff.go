package golib

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func FastFlags() {
	SetupFlags()
	flag.Parse()
	HandleFlags()
}

var Progname string

var ourFlags struct {
	version bool
}

func SetupFlags() {
	Progname = filepath.Base(os.Args[0])
	flag.BoolVar(&ourFlags.version, "version", false, "show version stuff and exit")
}

func HandleFlags() {
	if ourFlags.version {
		ShowVersion()
		os.Exit(0)
	}
}

func Stderr(spec string, args ...interface{}) {
	call := make([]interface{}, 1, 1+len(args))
	call[0] = Progname
	call = append(call, args...)
	fmt.Fprintf(os.Stderr, "%s: "+spec+"\n", call...)
}
