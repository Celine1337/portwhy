<p align="center">
  <img src="assets/banner.svg" width="830" alt="portwhy banner">
</p>
<p align="center">
  <a href="https://github.com/Celine1337/portwhy/releases"><img src="assets/nav-releases.svg" alt="Releases"></a>
  <a href="https://man7.org/linux/man-pages/man5/proc.5.html"><img src="assets/nav-spec.svg" alt="proc(5)"></a>
  <a href="LICENSE"><img src="assets/nav-mit.svg" alt="MIT"></a>
</p>

<img src="assets/section-about.svg" width="830" alt="About">

**portwhy** answers the question `ss -tlnp` only half-answers: *who owns that port, and how did it get there?* It reads the kernel's socket tables (`/proc/net/tcp` and `/proc/net/tcp6`), keeps only `LISTEN` sockets, matches each socket inode against `/proc/<pid>/fd/*` symlinks to find the owning process — then keeps going. For every listener it reports the full command line, the **parent ancestry** (a `PPid` walk up to init), the **cgroup**, and the **systemd unit** when one is detectable. That turns "something is on :8080" into "the dev server I launched from a terminal inside `app.slice`, whose parent shell is still alive".

It is a single static Go binary with **zero dependencies beyond the standard library**. No root required: processes you cannot inspect are reported as sockets with an invisible owner, and unreadable `/proc` entries are skipped silently instead of aborting the scan.

<img src="assets/section-features.svg" width="830" alt="Features">

- **Full ownership chain** — port → socket inode → PID → comm → cmdline → ancestry → cgroup → systemd unit, in one pass.
- **IPv4 + IPv6** — decodes the kernel's little-endian hex addresses (`0100007F:1F90` → `127.0.0.1:8080`, `::1`, `::` included).
- **LISTEN only** — established connections, TIME_WAIT and other states never pollute the output.
- **Graceful without root** — foreign listeners show `pid=?` with a clear note; your own processes get full forensics.
- **`--json`** — stable, indented JSON array (never `null`) for scripting and monitoring glue.
- **Deterministic ordering** — sorted by port, protocol, address, inode; identical runs produce identical output.
- **Testable by design** — `PORTWHY_PROC` repoints the `/proc` root, so the suite asserts parsing against a synthetic kernel tree *and* against a real live listener.

<img src="assets/section-stack.svg" width="830" alt="Tech stack">

<img src="assets/section-install.svg" width="830" alt="Install">

Requires Go 1.27+ and Linux (it is `/proc` forensics, after all).

```bash
git clone https://github.com/Celine1337/portwhy.git
cd portwhy
./build.sh          # go vet + go build -> bin/portwhy
./bin/portwhy 8080
```

The binary is self-contained; copy `bin/portwhy` anywhere on the same architecture.

<img src="assets/section-usage.svg" width="830" alt="Usage">

```bash
portwhy              # every listening TCP socket
portwhy 8080         # just port 8080
portwhy 8080 --json  # structured output
portwhy --help
```

```text
$ portwhy 8080
tcp 127.0.0.1:8080  pid=4242 comm=testd
  cmdline: testd --flag
  ancestry: 4200(bash) <- 1(systemd)
  cgroup: 0::/system.slice/demo.service
  unit: demo.service
```

Exit codes: `0` success (including "nothing listens on that port"), `2` bad usage or an unreadable `/proc`. Environment: `PORTWHY_PROC` overrides the `/proc` root (used by the test suite).

`./test.sh` runs 23 assertions: a synthetic `/proc` tree covering hex decoding, inode matching, ancestry, cgroups and units, plus a live end-to-end check that starts its own ephemeral TCP listener, verifies the reported PID/port, and kills only that listener.

<img src="assets/section-license.svg" width="830" alt="License">

MIT — see [LICENSE](LICENSE).