Self-Build Tools
================

A framework for writing small tools in Go which are invoked as regular
commands, using compiled builds.

Think "go run" but with executable tools, and only compiling when something
has changed.

Every tool has a useful `--version` output, with git identifying information.

This is a demonstration project, suitable for forking and using for your own
tools.


## How to use

You should be able to invoke a tool in the bin directory as-is.  This section
is really about how to take ownership and start extending with your own tools.

Place the `bin/` directory of the checkout of this repo in your `$PATH`
_ahead of_ `~/go/bin/`.  Eg:

```sh
PATH="$HOME/bin:$HOME/src/self-build-tools/bin:$HOME/go/bin:/usr/bin:/bin:/usr/local/bin"
export PATH
```

That should be enough for things to work.  Read on for extending.


## Extending

Pick a namespace of your own to replace `example.org/private`; things will
work with the defaults, but identification of origin in binaries will make
life better when you're later trying to identify things.

Edit `src/go.mod` and `src/go_compile_cache` to set the module and namespace
entries accordingly, at the top of the files.  Adjust the import paths in the
go source files.

Whenever you create a new .go file, be sure to import the golib library and
call `golib.FastFlags()` at the start of `main()`, or break that out into
individual calls if wanted.  The variables for version information live inside
golib, and that also provides the `-version` flag handling.  Drop a symlink to
the wrapper script into the `bin/` dir with a name which matches the go source
file without the `.go` extension.

So if you create `src/foo.go` then create a symlink `bin/foo` pointing to
`../src/go_compile_cache`.

The `// +build exclude_except_for_go_mod` build constraint is very much like
`// +build ignore` except that `go mod` won't ignore the files, so you get
dependency tracking in `go.mod` which works, even while you have several
different files each in `package main` with their own `main()` functions in
the one directory.


## Rebuilds

The tools are compiled and placed into `~/go/bin/` by default.  Whenever the
source file, or the `go.sum` dependencies file, are newer than the compiled
tool (or the compiled tool doesn't exist), the wrapper script will
automatically recompile the tool.  Various pieces of metadata are taken from
the git repo, including both the current commit of the repo _and_ the latest
commit which modified this tool in question, and both sets are embedded.

Just invoking the wrapper should be enough.  Using the `--version` parameter
is probably a good way to see the results.

Note that you can also use `go version -m ~/go/bin/compiled-tool-name` to
extract more data about a given tool, including all the module dependencies.
This is where changing the namespace away from `example.org/private` will pay
off, as the `mod` lines will give you something more useful for your
environment.


## Portability

This is known to work on Linux (glibc and musl) and FreeBSD.  The wrapper
script is POSIX sh, and the only tools which are not "very standard POSIX" we
depend upon are `git` and `go`.

The binaries are placed in `~/go/bin/` on the assumption that this is safe for
any given architecture.  If you have a home-directory shared over NFS for use
on multiple architectures, adjust the `exedir` definition in
`go_compile_cache`.


## History

This is taken from a personal tools & settings repo, which contains far more
than just these tools.  The pattern works well enough to be useful.


## TODO

It might be worth having a pre-commit hook which checks that for every .go
file, there exists a symlink in the bin directory.


## Demonstration Commands

 * `dns_ask_auth`: issue a DNS query to each of the authoritative nameservers
   for the domains of the parameters, asking for the value from each and
   showing them.  This is useful for consistency checks.  The default qtype is
   `TXT`, and `SOA` is a useful choice for seeing if the SOA serials are
   consistent.
 * `dns_cache_warm`: a way to ask multiple DNS recursors a large number of
   queries in parallel, useful for pre-warming DNS caches.
   + This expects a configuration file, default at
     `~/etc/dns-cache-warm.conf`, and an example is in the `etc/` directory.
   + This is not the greatest code, but it works for my purposes.  The
     configuration file was originally written to drive a shell script which
     invoked `host` or `dig`, so there are some unhandled combinations in the
     revamp.
   + Invoke with `--progress` to reduce the number of lines emitted; during
     resolution, a count of resolutions queries done so far will be
     repeatedly updated on one line, before being replaced with the summary
     when done.

I use a wrapper `dns_cache_warm_home` which puts some `.home.arpa` hostnames
into the `DNS_CACHE_EXTRA_RESOLVE` environment variable and invokes
`dns_cache_warm` with `--progress` and the IP addresses of the DNS resolvers
on my home LAN.  The extra hostnames are not in the committed file because
that is shared beyond my home network.
