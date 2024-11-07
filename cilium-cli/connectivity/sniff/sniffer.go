// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sniff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/lock"
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
	mode     Mode
	cmd      []string

	stdout lock.Buffer
	cancel context.CancelFunc
	exited chan error
}

type debugLogger interface {
	Debugf(string, ...interface{})
}

// Start starts a tcpdump capture on the given pod, listening to the specified
// interface. The mode configures whether Validate() will (not) expect any packet
// to match the filter.
func Sniff(ctx context.Context, name string, target *check.Pod,
	iface string, filter string, mode Mode, dbg debugLogger,
) (*Sniffer, error) {
	cmdctx, cancel := context.WithCancel(ctx)
	sniffer := &Sniffer{
		target:   target,
		dumpPath: fmt.Sprintf("/tmp/%s.pcap", name),
		mode:     mode,
		cancel:   cancel,
		exited:   make(chan error, 1),
	}

	go func() {
		// Run tcpdump with -w instead of directly printing captured pkts. This
		// is to avoid a race after sending ^C (triggered by cancel()) which
		// might terminate the tcpdump process before it gets a chance to dump
		// its captures.
		args := []string{"-i", iface, "--immediate-mode", "-w", sniffer.dumpPath}
		if sniffer.mode == ModeSanity {
			// We limit the number of packets to be captured only when expecting
			// them to be seen (i.e., in sanity mode). Otherwise, better to capture
			// them all to provide more informative debug messages on failures.
			args = append(args, "-c", "1")
		}
		sniffer.cmd = append([]string{"tcpdump"}, append(args, filter)...)

		dbg.Debugf("Running sniffer in background on %s (%s), mode=%s: %s",
			target.String(), target.NodeName(), mode, strings.Join(sniffer.cmd, " "))
		err := target.K8sClient.ExecInPodWithWriters(ctx, cmdctx,
			target.Pod.Namespace, target.Pod.Name, "", sniffer.cmd, &sniffer.stdout, io.Discard)
		if err != nil {
			sniffer.exited <- err
		}

		close(sniffer.exited)
	}()

	// Wait until tcpdump is ready to capture pkts
	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	defer wcancel()
	for {
		select {
		case <-wctx.Done():
			return nil, fmt.Errorf("Failed to wait for tcpdump to be ready")
		case err := <-sniffer.exited:
			if err == nil {
				// When running in sanity mode, tcpdump exits after capturing a
				// single packet matching the filter. Hence, it is possible that
				// it already terminated at this point. We'll then double check
				// whether it was the case when performing validation.
				return sniffer, nil
			}

			return nil, fmt.Errorf("Failed to execute tcpdump: %w", err)
		case <-time.After(100 * time.Millisecond):
			line, err := sniffer.stdout.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("Failed to read kubectl exec's stdout: %w", err)
			}
			if strings.Contains(line, fmt.Sprintf("listening on %s", iface)) {
				return sniffer, nil
			}
		}
	}
}

// Validate stops the tcpdump capture previously started by Sniff and asserts that
// no packets (or at least one packet when running in sanity mode) got captured. It
// additionally dumps the captured packets in case of failure if debug logs are enabled.
func (sniffer *Sniffer) Validate(ctx context.Context, a *check.Action) {
	// Wait until tcpdump has exited
	if err := sniffer.stopAndWait(ctx); err != nil {
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

func (sniffer *Sniffer) stopAndWait(ctx context.Context) error {
	select {
	case err := <-sniffer.exited:
		// When running in assert mode, it is an error if tcpdump already stopped
		// at this point, as we may have missed packets. That's not the case in
		// sanity mode, as configured to stop after receiving a single packet.
		if err == nil && sniffer.mode == ModeAssert {
			return errors.New("tcpdump terminated unexpectedly")
		}
		return err

	default:
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()

		sniffer.cancel()
		select {
		case err := <-sniffer.exited:
			// We canceled the context, so this is expected.
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err

		case <-ctx.Done():
			return errors.New("failed to wait for tcpdump to terminate")
		}
	}
}
