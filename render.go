// Output rendering: human-readable blocks and structured JSON.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// renderText prints one block per listener: the socket line plus whatever
// owner forensics were discoverable without extra privileges.
func renderText(w io.Writer, listeners []Listener, port int) {
	if len(listeners) == 0 {
		if port != 0 {
			fmt.Fprintf(w, "no listener on port %d\n", port)
		} else {
			fmt.Fprintln(w, "no listening sockets found")
		}
		return
	}
	for i, l := range listeners {
		if i > 0 {
			fmt.Fprintln(w)
		}
		pid, comm := "?", "?"
		if l.PID != 0 {
			pid = strconv.Itoa(l.PID)
		}
		if l.Comm != "" {
			comm = l.Comm
		}
		fmt.Fprintf(w, "%s %s:%d  pid=%s comm=%s\n", l.Proto, l.Address, l.Port, pid, comm)
		if l.PID == 0 {
			fmt.Fprintln(w, "  owner: not visible (process outside your permissions)")
			continue
		}
		if l.Cmdline != "" {
			fmt.Fprintf(w, "  cmdline: %s\n", l.Cmdline)
		}
		if len(l.Ancestry) > 0 {
			parts := make([]string, 0, len(l.Ancestry))
			for _, a := range l.Ancestry {
				parts = append(parts, fmt.Sprintf("%d(%s)", a.PID, a.Comm))
			}
			fmt.Fprintf(w, "  ancestry: %s\n", strings.Join(parts, " <- "))
		}
		if l.Cgroup != "" {
			fmt.Fprintf(w, "  cgroup: %s\n", l.Cgroup)
		}
		if l.Unit != "" {
			fmt.Fprintf(w, "  unit: %s\n", l.Unit)
		}
	}
}

// renderJSON emits a stable array (never null) for scripting.
func renderJSON(w io.Writer, listeners []Listener) error {
	if listeners == nil {
		listeners = []Listener{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(listeners)
}