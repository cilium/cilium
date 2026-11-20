// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapshotSample returns the stderr of one snapshot with the given values.
func snapshotSample(uptime, estabResets, challengeACK, cgroupSome, nodeSome, steal string) string {
	m := clientSnapshotMarker
	return m + " /proc/uptime\n" +
		uptime + " 3000.50\n" +
		m + " /proc/net/snmp\n" +
		"Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards\n" +
		"Ip: 1 64 1291 0 0 0 0 4\n" +
		"IcmpMsg:\n" +
		"IcmpMsg:\n" +
		"Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n" +
		"Tcp: 1 200 120000 -1 148 3 0 " + estabResets + " 2 1204 1198 7 0 5 0\n" +
		m + " /proc/net/netstat\n" +
		"TcpExt: SyncookiesSent TCPTimeouts TCPSynRetrans TCPChallengeACK TCPLostRetransmit\n" +
		"TcpExt: 0 3 2 " + challengeACK + " 6\n" +
		"IpExt: InNoRoutes InTruncatedPkts\n" +
		"IpExt: 0 0\n" +
		m + " /sys/fs/cgroup/cpu.pressure\n" +
		"some avg10=0.00 avg60=0.00 avg300=0.00 total=" + cgroupSome + "\n" +
		"full avg10=0.00 avg60=0.00 avg300=0.00 total=1\n" +
		m + " /proc/pressure/cpu\n" +
		"some avg10=0.00 avg60=3.61 avg300=3.56 total=" + nodeSome + "\n" +
		"full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n" +
		m + " /proc/stat\n" +
		"cpu  809276 1491 239292 18791523 59806 19924 10459 " + steal + " 0 0\n" +
		"cpu0 51235 498 15778 1169186 6190 1361 848 0 0 0\n" +
		"ctxt 123456\n" +
		m + " end\n"
}

func TestSplitClientSnapshots(t *testing.T) {
	const curlErr = "curl: (28) SSL connection timeout\n"
	stderr := snapshotSample("1123.45", "10", "1", "500000", "7000000", "12") +
		curlErr +
		snapshotSample("1125.46", "11", "1", "1700000", "7600000", "15")

	snaps, rest := splitClientSnapshots(stderr)
	assert.Equal(t, curlErr, rest)
	require.Len(t, snaps, 2)

	assert.Equal(t, clientSnapshot{
		snapUptime:                 1123450000,
		"Tcp:EstabResets":          10,
		"Tcp:OutRsts":              5,
		"Tcp:InErrs":               0,
		"Tcp:InCsumErrors":         0,
		"Tcp:RetransSegs":          7,
		"TcpExt:TCPChallengeACK":   1,
		"TcpExt:TCPLostRetransmit": 6,
		"TcpExt:TCPSynRetrans":     2,
		"TcpExt:TCPTimeouts":       3,
		"Ip:InDiscards":            4,
		snapCgroupSome:             500000,
		snapNodeSome:               7000000,
		snapNodeSteal:              120000,
	}, snaps[0])

	assert.Equal(t, "uptime=2.01s Tcp:EstabResets=1 Tcp:OutRsts=0 Tcp:InErrs=0"+
		" Tcp:InCsumErrors=0 Tcp:RetransSegs=0 TcpExt:TCPChallengeACK=0"+
		" TcpExt:TCPLostRetransmit=0 TcpExt:TCPSynRetrans=0 TcpExt:TCPTimeouts=0"+
		" Ip:InDiscards=0 cgroup_cpu_some=1.2s node_cpu_some=600ms node_steal=30ms",
		clientSnapshotDelta(snaps[0], snaps[1]))
}

func TestSplitClientSnapshotsMissingFiles(t *testing.T) {
	// cgroup v1 and kernels without PSI leave the cat output empty.
	m := clientSnapshotMarker
	before := m + " /proc/uptime\n100.00 50.00\n" + m + " /sys/fs/cgroup/cpu.pressure\n" + m + " end\n"
	after := m + " /proc/uptime\n102.50 50.00\n" + m + " /sys/fs/cgroup/cpu.pressure\n" + m + " end\n"

	// curl's error has no trailing newline, so the next marker shares its line.
	snaps, rest := splitClientSnapshots(before + "curl: (35) reset" + after)
	assert.Equal(t, "curl: (35) reset", rest)
	require.Len(t, snaps, 2)
	assert.Equal(t, "uptime=2.5s", clientSnapshotDelta(snaps[0], snaps[1]))
	assert.Equal(t, "none", clientSnapshotDelta(clientSnapshot{}, snaps[1]))
}

func TestSplitClientSnapshotsTruncated(t *testing.T) {
	// The splitter drops a snapshot without its end marker, content included.
	stderr := snapshotSample("1.00", "0", "0", "0", "0", "0") +
		"curl: (35) reset\n" +
		clientSnapshotMarker + " /proc/uptime\n3.00 1.00\n"

	snaps, rest := splitClientSnapshots(stderr)
	assert.Len(t, snaps, 1)
	assert.Equal(t, "curl: (35) reset\n", rest)

	snaps, rest = splitClientSnapshots("curl: (35) reset\n")
	assert.Empty(t, snaps)
	assert.Equal(t, "curl: (35) reset\n", rest)
}

func TestCurlWithClientSnapshotsExec(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh in PATH")
	}

	run := func(cmd ...string) (string, string, int) {
		argv := curlWithClientSnapshots(cmd)
		var stdout, stderr bytes.Buffer
		c := exec.Command(argv[0], argv[1:]...)
		c.Stdout, c.Stderr = &stdout, &stderr
		code := 0
		if err := c.Run(); err != nil {
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			code = exitErr.ExitCode()
		}
		return stdout.String(), stderr.String(), code
	}

	// Arguments reach the command unchanged and stdout carries only its output.
	stdout, stderr, code := run("printf", "%s|", "a b", `"c"`, "$HOME")
	assert.Equal(t, 0, code)
	assert.Equal(t, `a b|"c"|$HOME|`, stdout)
	snaps, rest := splitClientSnapshots(stderr)
	assert.Len(t, snaps, 2)
	assert.Empty(t, rest)

	// The wrapped command keeps its own exit status and stderr.
	stdout, stderr, code = run("sh", "-c", `echo out; echo "curl: (35) reset" >&2; exit 35`)
	assert.Equal(t, 35, code)
	assert.Equal(t, "out\n", stdout)
	snaps, rest = splitClientSnapshots(stderr)
	assert.Len(t, snaps, 2)
	assert.Equal(t, "curl: (35) reset\n", rest)
}
