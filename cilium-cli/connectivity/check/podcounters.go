// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// clientSnapshotMarker delimits the snapshots that curlWithClientSnapshots writes to stderr.
const clientSnapshotMarker = "@@cilium-cli-snapshot@@"

// clientSnapshotFiles lists what a snapshot reads in the client pod.
var clientSnapshotFiles = []string{
	"/proc/uptime",
	"/proc/net/snmp",
	"/proc/net/netstat",
	"/sys/fs/cgroup/cpu.pressure",
	"/proc/pressure/cpu",
	"/proc/stat",
}

// clientCounterNames lists the /proc/net/snmp and /proc/net/netstat counters a clientSnapshot keeps.
var clientCounterNames = []string{
	"Tcp:EstabResets",
	"Tcp:OutRsts",
	"Tcp:InErrs",
	"Tcp:InCsumErrors",
	"Tcp:RetransSegs",
	"TcpExt:TCPChallengeACK",
	"TcpExt:TCPLostRetransmit",
	"TcpExt:TCPSynRetrans",
	"TcpExt:TCPTimeouts",
	"Ip:InDiscards",
}

// Names of the clientSnapshot values that hold microseconds.
const (
	snapUptime     = "uptime"
	snapCgroupSome = "cgroup_cpu_some"
	snapNodeSome   = "node_cpu_some"
	snapNodeSteal  = "node_steal"
)

// clientSnapshotNames orders the values of a logged delta.
var clientSnapshotNames = slices.Concat([]string{snapUptime}, clientCounterNames,
	[]string{snapCgroupSome, snapNodeSome, snapNodeSteal})

// userHZ gives the tick rate of the /proc/stat CPU columns.
const userHZ = 100

// clientSnapshot holds one read of clientSnapshotFiles, keyed by clientSnapshotNames.
type clientSnapshot map[string]int64

// curlWithClientSnapshots wraps cmd in a shell that writes a snapshot to stderr right before and right after it.
func curlWithClientSnapshots(cmd []string) []string {
	snap := fmt.Sprintf(`{ for f in %s; do echo "%s $f"; cat "$f" 2>/dev/null; done; echo "%s end"; } >&2`,
		strings.Join(clientSnapshotFiles, " "), clientSnapshotMarker, clientSnapshotMarker)
	return append([]string{"sh", "-c", snap + `; "$@"; rc=$?; ` + snap + `; exit $rc`, "sh"}, cmd...)
}

// splitClientSnapshots returns the snapshots found in stderr, oldest first, and stderr without them.
func splitClientSnapshots(stderr string) ([]clientSnapshot, string) {
	var (
		snaps []clientSnapshot
		rest  strings.Builder
		files map[string]string // file name => content, nil outside a snapshot
		cur   string
	)
	for line := range strings.Lines(stderr) {
		before, marker, found := strings.Cut(line, clientSnapshotMarker)
		if files == nil {
			rest.WriteString(before)
		} else {
			files[cur] += before
		}
		if !found {
			continue
		}
		if cur = strings.TrimSpace(marker); cur == "end" {
			if files != nil {
				snaps = append(snaps, parseClientSnapshot(files))
			}
			files = nil
		} else if files == nil {
			files = make(map[string]string, len(clientSnapshotFiles))
		}
	}
	return snaps, rest.String()
}

func parseClientSnapshot(files map[string]string) clientSnapshot {
	snap := parseNetCounters(files["/proc/net/snmp"] + files["/proc/net/netstat"])
	if f := strings.Fields(files["/proc/uptime"]); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			snap[snapUptime] = int64(math.Round(v * 1e6))
		}
	}
	if v, ok := psiSomeTotal(files["/sys/fs/cgroup/cpu.pressure"]); ok {
		snap[snapCgroupSome] = v
	}
	if v, ok := psiSomeTotal(files["/proc/pressure/cpu"]); ok {
		snap[snapNodeSome] = v
	}
	for line := range strings.Lines(files["/proc/stat"]) {
		// cpu user nice system idle iowait irq softirq steal guest guest_nice
		if f := strings.Fields(line); len(f) > 8 && f[0] == "cpu" {
			if v, err := strconv.ParseInt(f[8], 10, 64); err == nil {
				snap[snapNodeSteal] = v * int64(time.Second/time.Microsecond) / userHZ
			}
			break
		}
	}
	return snap
}

// psiSomeTotal returns the total= field, in microseconds, of the "some" line of a PSI file.
func psiSomeTotal(out string) (int64, bool) {
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "some" {
			continue
		}
		for _, field := range f[1:] {
			if v, ok := strings.CutPrefix(field, "total="); ok {
				total, err := strconv.ParseInt(v, 10, 64)
				return total, err == nil
			}
		}
	}
	return 0, false
}

// parseNetCounters returns the clientCounterNames values of /proc/net/snmp and /proc/net/netstat.
func parseNetCounters(out string) clientSnapshot {
	counters := make(clientSnapshot, len(clientSnapshotNames))
	headers := make(map[string][]string)
	for line := range strings.Lines(out) {
		prefix, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		names, seen := headers[prefix]
		if !seen {
			headers[prefix] = fields
			continue
		}
		// The values line closes the pair, so a repeated prefix starts a new one.
		delete(headers, prefix)
		for i, name := range names {
			key := prefix + ":" + name
			if i >= len(fields) || !slices.Contains(clientCounterNames, key) {
				continue
			}
			if value, err := strconv.ParseInt(fields[i], 10, 64); err == nil {
				counters[key] = value
			}
		}
	}
	return counters
}

// clientSnapshotDelta renders after minus before for the values both snapshots hold.
func clientSnapshotDelta(before, after clientSnapshot) string {
	var deltas []string
	for _, name := range clientSnapshotNames {
		b, okBefore := before[name]
		a, okAfter := after[name]
		if !okBefore || !okAfter {
			continue
		}
		if slices.Contains(clientCounterNames, name) {
			deltas = append(deltas, fmt.Sprintf("%s=%d", name, a-b))
		} else {
			deltas = append(deltas, fmt.Sprintf("%s=%s", name, time.Duration(a-b)*time.Microsecond))
		}
	}
	if len(deltas) == 0 {
		return "none"
	}
	return strings.Join(deltas, " ")
}
