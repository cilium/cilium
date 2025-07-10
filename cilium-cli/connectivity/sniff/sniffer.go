// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sniff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
)

// Mode configures the Sniffer validation mode.
type Mode string

const (
	// ModeAssert: do not expect to observe any packets matching the filter.
	ModeAssert Mode = "assert"
	// ModeSanity: expect to observe packets matching the filter, to be
	// leveraged as a sanity check to verify that the filter is correct.
	ModeSanity Mode = "sanity"

	// Max wait time for tcpdump to start/stop in remote shell.
	sniffScriptTimeout = 10 * time.Second
	// Max timeout before aborting k8s connection in Start/Stop; must exceed sniffScriptTimeout.
	sniffConnectionTimeout = sniffScriptTimeout + 5*time.Second
	// Max remote sniffer runtime to prevent lingering processes in the pod.
	// NOTE: too low may kill tcpdump while test is running.
	sniffKillTimeout = sniffConnectionTimeout * 4

	// Command executed to start the remote tcpdump in background inside a pod.
	//
	// We send tcpdump output to a file inside the pod rather than stdout,
	// to avoid GH Issue #38643: tcpdump failing with error 14 due to one of
	// its output streams not being available anymore.
	// (tcpdump: Unable to write output: Broken pipe)
	//
	// Runs silently: succeeds if tcpdump is active ("listening on <iface>"),
	// else fails with its error code. Includes `timeout 60` to prevent orphaned
	// tcpdump if sniffer isn't properly stopped.
	sniffScriptStartTmpl = `
{
	# Cleanup any leftover files from previous runs.
	rm -f {{ .PidPath }} {{ .DumpPath }} {{ .LogPath }}

	# Start tcpdump directly in background and capture its PID.
	timeout {{ .KillSeconds }} tcpdump -i {{ .Iface }} {{ .Sanity }} --immediate-mode -U -w {{ .DumpPath }} "{{ .Filter }}" > {{ .LogPath }} 2>&1 &
	pid=$!
	echo $pid > {{ .PidPath }}

	# Wait for startup confirmation and exit with success.
	# Exit with error code if process is not running.
	for i in $(seq 1 {{ .WaitSeconds }}); do
		sleep 1
		grep -q "listening on {{ .Iface }}" {{ .LogPath }} && exit 0
		kill -0 $pid 2>/dev/null || {
			wait $pid
			exit $?
		}
	done

	# Process is running but did not receive confirmation, kill and exit.
	kill -9 $pid 2>/dev/null
	wait $pid
	exit $?
}
`

	// Command executed to stop the remote tcpdump inside a pod.
	sniffScriptStopTmpl = `
{
	# Ignore signals received when killing tcpdump.
	trap '' TERM INT HUP

	# Exit with error if tcpdump is not running.
	if [ ! -f "{{ .PidPath }}" ]; then
		exit 199
	fi

	pid=$(cat {{ .PidPath }} )

	# Kill the process if it is still running.
	# Return an error if tcpdump timed out before capturing any packets.
	if kill -0 $pid 2>/dev/null; then
		kill -2 $pid 2>/dev/null
	elif [ "$(tcpdump -r {{ .DumpPath }} --count 2>/dev/null)" = "0 packets" ]; then
		exit 198
	else
		exit 0
	fi

	# Confirm that process has been stopped and exit with success code.
	for i in $(seq 1 {{ .WaitSeconds }}); do
		if ! kill -0 $pid 2>/dev/null; then
			exit 0
		fi
		sleep 1
	done

	# Process still exists, exit with error.
	kill -9 $pid 2>/dev/null
	exit 197
}
`
)

type Sniffer struct {
	target   *check.Pod
	dumpPath string
	logPath  string
	pidPath  string
	mode     Mode
	cmd      []string
	stopCmd  []string
	once     sync.Once
}

type sniffScriptParams struct {
	LogPath     string
	DumpPath    string
	PidPath     string
	Iface       string
	Sanity      string
	Filter      string
	WaitSeconds int
	KillSeconds int
}

type debugLogger interface {
	Debugf(string, ...any)
}

// Start starts a tcpdump capture on the given pod, listening to the specified
// interface. The mode configures whether Validate() will (not) expect any packet
// to match the filter. The returned finalization/close function must be run
// to make sure the remote sniffer is properly closed, in case [*Sniffer.Validate] has
// not been called (e.g., expired context or error in between).
func Sniff(ctx context.Context, name string, target *check.Pod,
	iface string, filter string, mode Mode, dbg debugLogger,
) (*Sniffer, func() error, error) {
	sniffer := &Sniffer{
		target:   target,
		dumpPath: fmt.Sprintf("/tmp/%s.pcap", name),
		logPath:  fmt.Sprintf("/tmp/%s.log", name),
		pidPath:  fmt.Sprintf("/tmp/%s.pid", name),
		mode:     mode,
	}

	var sanity string
	if sniffer.mode == ModeSanity {
		// We limit the number of packets to be captured only when expecting
		// them to be seen (i.e., in sanity mode). Otherwise, better to capture
		// them all to provide more informative debug messages on failures.
		sanity = "-c 1"
	}

	// Execute the template to have the final command.
	var buf bytes.Buffer
	tmpl := template.Must(template.New("sniffStart").Parse(sniffScriptStartTmpl))

	err := tmpl.Execute(&buf, sniffScriptParams{
		LogPath:     sniffer.logPath,
		DumpPath:    sniffer.dumpPath,
		PidPath:     sniffer.pidPath,
		Iface:       iface,
		Sanity:      sanity,
		Filter:      filter,
		WaitSeconds: int(sniffScriptTimeout.Seconds()),
		KillSeconds: int(sniffKillTimeout.Seconds()),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("template execution failed: %w", err)
	}

	// Finally wrap the resulting command.
	sniffer.cmd = append([]string{"nohup", "sh", "-c"}, buf.String())

	// Context with a max timeout to start tcpdump.
	ctx, cancel := context.WithTimeout(ctx, sniffConnectionTimeout)
	defer cancel()

	dbg.Debugf("Running sniffer in background on %s (%s), mode=%s: %s",
		target.String(), target.NodeName(), mode, strings.Join(sniffer.cmd, " "))
	if _, err := target.K8sClient.ExecInPod(ctx, target.Pod.Namespace, target.Pod.Name, "", sniffer.cmd); err != nil {
		err = fmt.Errorf("Failed to execute tcpdump: %w", err)
		if errors.Is(err, context.Canceled) {
			// Child/Parent context has been canceled, we now stop the remote
			// sniffer, despite tcpdump being wrapped within a `timeout`.
			err = errors.Join(err, sniffer.stop())
		}
		return nil, nil, err
	}

	return sniffer, sniffer.stop, nil
}

// Validate stops the tcpdump capture previously started by Sniff and asserts that
// no packets (or at least one packet when running in sanity mode) got captured. It
// additionally dumps the captured packets in case of failure if debug logs are enabled.
func (sniffer *Sniffer) Validate(ctx context.Context, a *check.Action) {
	// Stop tcpdump if needed.
	if err := sniffer.stop(); err != nil {
		a.Fatal(err)
	}

	// Redirect stderr to /dev/null, as tcpdump logs to stderr, and ExecInPod
	// will return an error if any char is written to stderr. Anyway, the count
	// is written to stdout.
	cmd := []string{"/bin/sh", "-c", fmt.Sprintf("tcpdump -r %s --count 2>/dev/null", sniffer.dumpPath)}
	count, err := sniffer.target.K8sClient.ExecInPod(ctx, sniffer.target.Pod.Namespace, sniffer.target.Pod.Name, "", cmd)
	if err != nil {
		a.Fatalf("Failed to retrieve tcpdump packet count on %s (%s): %s", sniffer.target.String(), sniffer.target.NodeName(), err)
	}

	if !strings.Contains(count.String(), "packet") {
		a.Fatalf("tcpdump output doesn't look correct on %s (%s): %s", sniffer.target.String(), sniffer.target.NodeName(), count.String())
	}

	if !strings.HasPrefix(count.String(), "0 packets") && sniffer.mode == ModeAssert {
		a.Failf("Captured unexpected packets (count=%s)", strings.TrimRight(count.String(), "\n\r"))
		a.Infof("Capture executed on %s (%s): %s", sniffer.target.String(), sniffer.target.NodeName(), strings.Join(sniffer.cmd, " "))

		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("tcpdump -r %s 2>/dev/null", sniffer.dumpPath)}
		out, err := sniffer.target.K8sClient.ExecInPod(ctx, sniffer.target.Pod.Namespace, sniffer.target.Pod.Name, "", cmd)
		if err != nil {
			a.Fatalf("Failed to retrieve tcpdump output on %s (%s): %s", sniffer.target.String(), sniffer.target.NodeName(), err)
		}
		a.Infof("Captured packets:\n%s", out.String())
	}

	if strings.HasPrefix(count.String(), "0 packets") && sniffer.mode == ModeSanity {
		a.Failf("Expected to capture packets, but none found. This check might be broken.")
		a.Infof("Capture executed on %s (%s): %s", sniffer.target.String(), sniffer.target.NodeName(), strings.Join(sniffer.cmd, " "))
	}
}

// stop runs the remote command to kill the sniffer process. It executes at most once.
func (sniffer *Sniffer) stop() (err error) {
	if sniffer == nil {
		return
	}

	sniffer.once.Do(func() {
		// Execute the template with only the needed params.
		var buf bytes.Buffer
		tmpl := template.Must(template.New("sniffStop").Parse(sniffScriptStopTmpl))

		err = tmpl.Execute(&buf, sniffScriptParams{
			PidPath:     sniffer.pidPath,
			WaitSeconds: int(sniffScriptTimeout.Seconds()),
		})
		if err != nil {
			err = fmt.Errorf("template execution failed: %w", err)
			return
		}

		// Finally wrap the resulting command.
		sniffer.stopCmd = append([]string{"sh", "-c"}, buf.String())

		// Context with timeout for stopping tcpdump.
		// NOTE: Context is not passed anymore to this function to avoid premature cancellation.
		ctx, cancel := context.WithTimeout(context.Background(), sniffConnectionTimeout)
		defer cancel()

		// Stop tcpdump.
		_, err = sniffer.target.K8sClient.ExecInPod(ctx, sniffer.target.Pod.Namespace, sniffer.target.Pod.Name, "", sniffer.stopCmd)
		if err != nil {
			err = fmt.Errorf("Failed to stop tcpdump on %s (%s): %w", sniffer.target.String(), sniffer.target.NodeName(), err)
		}
	})

	return
}
