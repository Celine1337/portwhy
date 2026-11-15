// Socket-table parsing: /proc/net/tcp and /proc/net/tcp6.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Listener describes one listening TCP socket and, when discoverable, its owner.
type Listener struct {
	Proto    string     `json:"proto"`
	Address  string     `json:"address"`
	Port     int        `json:"port"`
	Inode    uint64     `json:"inode"`
	PID      int        `json:"pid"` // 0 = owner not visible without more privileges
	Comm     string     `json:"comm,omitempty"`
	Cmdline  string     `json:"cmdline,omitempty"`
	Ancestry []Ancestor `json:"ancestry,omitempty"`
	Cgroup   string     `json:"cgroup,omitempty"`
	Unit     string     `json:"unit,omitempty"`
}

// Ancestor is one step of the PPid walk above the owning process.
type Ancestor struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
}

// procRoot honors PORTWHY_PROC so tests can point at a synthetic /proc tree.
func procRoot() string {
	if r := os.Getenv("PORTWHY_PROC"); r != "" {
		return r
	}
	return "/proc"
}

// decodeAddr turns the kernel's little-endian hex address into a printable IP.
// IPv4 is one 32-bit word; IPv6 is four 32-bit words, each byte-reversed.
func decodeAddr(h string, v6 bool) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", fmt.Errorf("bad address %q: %w", h, err)
	}
	if v6 {
		if len(b) != 16 {
			return "", fmt.Errorf("bad IPv6 address %q", h)
		}
		for w := 0; w < 4; w++ {
			o := w * 4
			b[o], b[o+1], b[o+2], b[o+3] = b[o+3], b[o+2], b[o+1], b[o]
		}
		return net.IP(b).String(), nil
	}
	if len(b) != 4 {
		return "", fmt.Errorf("bad IPv4 address %q", h)
	}
	return net.IPv4(b[3], b[2], b[1], b[0]).String(), nil
}

// parseProcNet reads one kernel socket table and keeps only LISTEN (0A) rows.
func parseProcNet(path, proto string) ([]Listener, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Listener
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		host, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		addr, err := decodeAddr(host, proto == "tcp6")
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, Listener{Proto: proto, Address: addr, Port: int(port), Inode: inode})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// collectListeners merges both socket tables. A missing tcp6 file is normal
// (IPv6 disabled); only a completely unreadable /proc is an error.
func collectListeners(root string) ([]Listener, error) {
	var out []Listener
	readAny := false
	for _, t := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp6"}} {
		ls, err := parseProcNet(filepath.Join(root, "net", t.file), t.proto)
		if err != nil {
			continue
		}
		readAny = true
		out = append(out, ls...)
	}
	if !readAny {
		return nil, fmt.Errorf("cannot read %s/net/tcp or %s/net/tcp6", root, root)
	}
	return out, nil
}