package golib

import (
	"fmt"
	"strconv"
	"time"
)

var (
	CompileTimeEpochSecs string
	GitVersion           string
	GitCommit            string
	GitBranch            string
	GitDate              string
	ToolCommit           string
	ToolDate             string
)

func epochTimeRender(epochSecs string) string {
	if epochSecs == "" {
		return "<not supplied>"
	}
	secs64, err := strconv.ParseInt(epochSecs, 10, 64)
	if err != nil {
		return fmt.Sprintf("[[time %q unparsed as int64: %v]]", epochSecs, err)
	}
	return time.Unix(secs64, 0).UTC().Format("2006-01-02 15:04Z [Monday January 2, in UTC]")
}

func ShowVersion() {
	Stderr("compilation time: %s", epochTimeRender(CompileTimeEpochSecs))
	Stderr("git version: %q branch: %q", GitVersion, GitBranch)
	Stderr("git tool commit: %s", ToolCommit)
	Stderr("git tool commit date: %s", epochTimeRender(ToolDate))
	Stderr("git repo commit: %s", GitCommit)
	Stderr("git repo commit date: %s", epochTimeRender(GitDate))
}
