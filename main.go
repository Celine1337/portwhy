// portwhy - listening-socket forensics.
//
// Answers "who owns that port, and how did it get there?" by reading
// /proc/net/tcp{,6}, matching socket inodes against /proc/<pid>/fd symlinks,
// and walking the owning process's ancestry, cgroup and systemd unit.
// Standard library only; no root required (foreign processes are reported
// without owner details).
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
)

const usage = `portwhy - listening-socket forensics: who owns that port, and why

usage: portwhy [port] [--json]

  port      1-65535; omit to list every listening socket
  --json    structured JSON output
  -h        show this help

Reads /proc/net/tcp and /proc/net/tcp6 (state 0A = LISTEN), matches socket
inodes to /proc/<pid>/fd/* symlinks, then reports the owning PID, process
name, full cmdline, parent ancestry, cgroup and systemd unit (if any).
Unreadable /proc entries are skipped silently, so it works without root.

exit codes: 0 success (including "nothing listens"), 2 usage or I/O error
environment: PORTWHY_PROC overrides the /proc root (testing hook)
`

type options struct {
	port    int // 0 = all listeners
	jsonOut bool
	help    bool
}

func parseArgs(args []string) (options, error) {
	var o options
	positional := 0
	for _, a := range args {
		switch a {
		case "--json", "-j":
			o.jsonOut = true
		case "--help", "-h":
			o.help = true
		default:
			if len(a) > 1 && a[0] == '-' {
				return o, fmt.Errorf("unknown flag %q", a)
			}
			positional++
			if positional > 1 {
				return o, fmt.Errorf("expected at most one port argument")
			}
			p, err := strconv.Atoi(a)
			if err != nil || p < 1 || p > 65535 {
				return o, fmt.Errorf("invalid port %q (want 1-65535)", a)
			}
			o.port = p
		}
	}
	return o, nil
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "portwhy:", err)
		fmt.Fprint(os.Stderr, "\n"+usage)
		os.Exit(2)
	}
	if opts.help {
		fmt.Print(usage)
		return
	}

	root := procRoot()
	listeners, err := collectListeners(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "portwhy:", err)
		os.Exit(2)
	}
	owners := scanOwners(root)
	for i := range listeners {
		enrich(&listeners[i], root, owners)
	}
	if opts.port != 0 {
		filtered := listeners[:0]
		for _, l := range listeners {
			if l.Port == opts.port {
				filtered = append(filtered, l)
			}
		}
		listeners = filtered
	}
	sort.Slice(listeners, func(i, j int) bool {
		a, b := listeners[i], listeners[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Inode < b.Inode
	})

	if opts.jsonOut {
		if err := renderJSON(os.Stdout, listeners); err != nil {
			fmt.Fprintln(os.Stderr, "portwhy:", err)
			os.Exit(2)
		}
		return
	}
	renderText(os.Stdout, listeners, opts.port)
}