// Owner discovery: socket inode -> PID via /proc/<pid>/fd, then process details.
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// scanOwners maps socket inodes to PIDs by reading every accessible
// /proc/<pid>/fd/* symlink. Unreadable processes are skipped silently, so a
// non-root run still finds everything it is allowed to see.
func scanOwners(root string) map[uint64]int {
	owners := make(map[uint64]int)
	entries, err := os.ReadDir(root)
	if err != nil {
		return owners
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(root, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inodeStr, ok := strings.CutPrefix(link, "socket:[")
			if !ok || !strings.HasSuffix(inodeStr, "]") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(inodeStr, "]"), 10, 64)
			if err != nil {
				continue
			}
			if _, dup := owners[inode]; !dup {
				owners[inode] = pid
			}
		}
	}
	return owners
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readPPid extracts the parent PID from /proc/<pid>/status.
func readPPid(root string, pid int) (int, bool) {
	f, err := os.Open(filepath.Join(root, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, false
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		v, ok := strings.CutPrefix(line, "PPid:")
		if !ok {
			continue
		}
		ppid, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return ppid, true
	}
	return 0, false
}

// walkAncestry follows PPid upward (bounded, cycle-safe) to init.
func walkAncestry(root string, pid int) []Ancestor {
	var chain []Ancestor
	seen := map[int]bool{pid: true}
	cur := pid
	for depth := 0; depth < 64; depth++ {
		ppid, ok := readPPid(root, cur)
		if !ok || ppid <= 0 || seen[ppid] {
			break
		}
		seen[ppid] = true
		chain = append(chain, Ancestor{
			PID:  ppid,
			Comm: readTrimmed(filepath.Join(root, strconv.Itoa(ppid), "comm")),
		})
		if ppid == 1 {
			break
		}
		cur = ppid
	}
	return chain
}

// detectUnit pulls a systemd unit name out of cgroup paths, e.g.
// "0::/system.slice/sshd.service" -> "sshd.service".
func detectUnit(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		for _, seg := range strings.Split(line, "/") {
			if strings.HasSuffix(seg, ".service") && len(seg) > len(".service") {
				return seg
			}
		}
	}
	return ""
}

// enrich fills in owner details for a listener whose inode matched a PID.
func enrich(l *Listener, root string, owners map[uint64]int) {
	pid, ok := owners[l.Inode]
	if !ok {
		return
	}
	l.PID = pid
	base := filepath.Join(root, strconv.Itoa(pid))
	l.Comm = readTrimmed(filepath.Join(base, "comm"))
	if b, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		l.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	}
	l.Ancestry = walkAncestry(root, pid)
	if raw := readTrimmed(filepath.Join(base, "cgroup")); raw != "" {
		var lines []string
		for _, ln := range strings.Split(raw, "\n") {
			if ln = strings.TrimSpace(ln); ln != "" {
				lines = append(lines, ln)
			}
		}
		l.Cgroup = strings.Join(lines, "; ")
		l.Unit = detectUnit(raw)
	}
}