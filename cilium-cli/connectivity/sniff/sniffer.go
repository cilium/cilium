// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sniff

import (
	"context"
	"fmt"
	"runtime"
	"strings"

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
)

type Sniffer struct {
	target   *check.Pod
	dumpPath string
	logPath  string
	mode     Mode
	cmd      []string
	stopCmd  []string
	running  bool
}

type debugLogger interface {
	Debugf(string, ...any)
}

// Start starts a tcpdump capture on the given pod, listening to the specified
// interface. The mode configures whether Validate() will (not) expect any packet
// to match the filter.
func Sniff(ctx context.Context, name string, target *check.Pod,
	iface string, filter string, mode Mode, dbg debugLogger,
) (*Sniffer, error) {
	sniffer := &Sniffer{
		target:   target,
		dumpPath: fmt.Sprintf("/tmp/%s.pcap", name),
		logPath:  fmt.Sprintf("/tmp/%s.log", name),
		mode:     mode,
	}

	// Run tcpdump with -w instead of directly printing captured pkts. This
	// is to avoid a race after sending ^C (triggered by cancel()) which
	// might terminate the tcpdump process before it gets a chance to dump
	// its captures.
	args := []string{"-i", iface, "-U", "-w", sniffer.dumpPath}
	if sniffer.mode == ModeSanity {
		// We limit the number of packets to be captured only when expecting
		// them to be seen (i.e., in sanity mode). Otherwise, better to capture
		// them all to provide more informative debug messages on failures.
		args = append(args, "-c", "1")
	}
	sniffer.cmd = append([]string{"tcpdump"}, append(args, "\""+filter+"\"")...)
	// We send tcpdump output to a file inside the pod rather than stdout,
	// to avoid GH Issue #38643: tcpdump failing with error 14 due to one of
	// its output streams (stdout in this case) not being available anymore.
	// (tcpdump: Unable to write output: Broken pipe)
	//
	// This command does not return any output, but succeeds if tcpdump
	// is listening on the interface.
	c := `
(
  rm -f %s %s
  %s >%s 2>&1 & 
  pid=$! 
  for i in $(seq 1 20); do
    sleep 1
    grep -q "listening on %s" %s && exit 0
    kill -0 $pid 2>/dev/null || {
      wait $pid
      exit $?
    }
  done 
  kill $pid 2>/dev/null
  wait $pid
  exit $?
)
`
	sniffer.cmd = append([]string{"nohup", "sh", "-c"}, fmt.Sprintf(c, sniffer.logPath, sniffer.dumpPath, strings.Join(sniffer.cmd, " "), sniffer.logPath, iface, sniffer.logPath))

	dbg.Debugf("Running sniffer in background on %s (%s), mode=%s: %s",
		target.String(), target.NodeName(), mode, strings.Join(sniffer.cmd, " "))
	_, err := target.K8sClient.ExecInPod(ctx, target.Pod.Namespace, target.Pod.Name, "", sniffer.cmd)
	if err != nil {
		return nil, fmt.Errorf("Failed to run tcpdump in background: %w", err)
	}

	sniffer.running = true
	// This is in case we forget to call stop() later in between tests or when
	// some Sniff fails while the previous one succeeded.
	// TODO: add stop() explicitly and don't rely on finalizers.
	runtime.SetFinalizer(sniffer, func(s *Sniffer) {
		s.stop(context.Background())
	})
	return sniffer, nil
}

// Validate stops the tcpdump capture previously started by Sniff and asserts that
// no packets (or at least one packet when running in sanity mode) got captured. It
// additionally dumps the captured packets in case of failure if debug logs are enabled.
func (sniffer *Sniffer) Validate(ctx context.Context, a *check.Action) {
	// Wait until tcpdump has exited
	if err := sniffer.stop(ctx); err != nil {
		a.Fatalf("Failed to execute tcpdump on %s (%s): %s", sniffer.target.String(), sniffer.target.NodeName(), err)
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

// TODO: we do have places where we init multiple Sniff. Be sure to call stop() even when, for instance, the 2nd Sniff fails.
func (sniffer *Sniffer) stop(ctx context.Context) error {
	if !sniffer.running {
		return nil
	}
	sniffer.running = false
	sniffer.stopCmd = append([]string{"sh", "-c"}, fmt.Sprintf("pkill -f 'tcpdump.*-w %s'", sniffer.dumpPath))
	_, err := sniffer.target.K8sClient.ExecInPod(ctx, sniffer.target.Pod.Namespace, sniffer.target.Pod.Name, "", sniffer.stopCmd)
	if err != nil {
		return fmt.Errorf("failed to stop tcpdump on %s (%s): %w", sniffer.target.String(), sniffer.target.NodeName(), err)
	}
	return nil
}
