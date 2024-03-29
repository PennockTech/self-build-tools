package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/tools/go/vcs"

	"example.org/private/selfbuild/golib"
)

const EX_USAGE = 64 // per sysexits.h

var opts struct {
	notReally bool
}

func registerFlags() {
	flag.BoolVar(&opts.notReally, "not-really", false, "don't actually clone, just show")
	flag.BoolVar(&opts.notReally, "n", false, "short for -not-really")
}

func main() {
	registerFlags()
	golib.FastFlags()
	retval := 0
	defer func() {
		if retval != 0 {
			os.Exit(retval)
		}
	}()

	importPaths := flag.Args()

	if len(importPaths) < 1 {
		retval = EX_USAGE
		golib.Stderr("need at least one Go import path to download")
		return
	}

	wrGosrc, err := gosrcWriteable()
	if err != nil {
		golib.Stderr("unable to get writeable GOPATH: %s", err)
		return
	}

	for _, p := range importPaths {
		if err = download(p, wrGosrc); err != nil {
			golib.Stderr("grab of %q failed: %s", p, err)
			if retval == 0 {
				retval = 1
			}
		}
	}
}

func download(importSpec string, wrGosrc string) error {
	for _, prefix := range []string{
		"https://",
		"http://",
	} {
		if strings.HasPrefix(importSpec, prefix) {
			importSpec = importSpec[len(prefix):]
			break
		}
	}
	repoRoot, err := vcs.RepoRootForImportPath(importSpec, false)
	if err != nil {
		return err
	}
	targetDir := filepath.Join(wrGosrc, repoRoot.Root)

	var safe bool

	if _, err := os.Stat(targetDir); err != nil {
		if os.IsNotExist(err) {
			safe = true
		}
	}

	if !safe {
		return fmt.Errorf("target dir %q already exists", targetDir)
	}

	actionMsg := "cloning"

	if opts.notReally {
		golib.Stderr("would: MkDirAll(%q)", filepath.Dir(targetDir))
		actionMsg = "would: clone"
	} else if err := os.MkdirAll(filepath.Dir(targetDir), 0o755); err != nil {
		return fmt.Errorf("creating parents of %q failed: %w", targetDir, err)
	}

	golib.Stderr("%s %s repo from %q to %q", actionMsg, repoRoot.VCS.Name, repoRoot.Repo, targetDir)
	if opts.notReally {
		return nil
	}
	return repoRoot.VCS.Create(targetDir, repoRoot.Repo)
}

func gosrcWriteable() (string, error) {
	var err error
	p := os.Getenv("GOPATH")
	if p == "" {
		p, err = homedir.Expand("~/go")
		if err != nil {
			return "", err
		}
	}
	pathElems := filepath.SplitList(p)
	if len(pathElems) < 1 {
		return "", errors.New("GOPATH is explicitly empty")
	}
	d := filepath.Join(pathElems[0], "src")
	return d, nil
}
