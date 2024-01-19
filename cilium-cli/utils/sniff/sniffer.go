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

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/lock"
)

type Sniffer struct {
	host     *check.Pod
	dumpPath string

	stdout lock.Buffer
	cancel context.CancelFunc
	exited chan error
}

func Sniff(ctx context.Context, t *check.Test, host *check.Pod,
	iface string, filter string,
) (*Sniffer, error) {
	cmdctx, cancel := context.WithCancel(ctx)
	sniffer := &Sniffer{
		host:     host,
		dumpPath: fmt.Sprintf("/tmp/%s-%s.pcap", t.Name(), host.Pod.Name),
		cancel:   cancel,
		exited:   make(chan error, 1),
	}

	go func() {
		// Run tcpdump with -w instead of directly printing captured pkts. This
		// is to avoid a race after sending ^C (triggered by cancel()) which
		// might terminate the tcpdump process before it gets a chance to dump
		// its captures.
		cmd := []string{
			"tcpdump", "-i", iface, "--immediate-mode",
			"-w", sniffer.dumpPath, filter,
		}

		t.Debugf("Running in bg: %s", strings.Join(cmd, " "))
		err := host.K8sClient.ExecInPodWithWriters(ctx, cmdctx,
			host.Pod.Namespace, host.Pod.Name, "", cmd, &sniffer.stdout, io.Discard)
		if err != nil && !errors.Is(err, context.Canceled) {
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

func (sniffer *Sniffer) Validate(ctx context.Context, a *check.Action, assertNoLeaks, debug bool) {
	// Wait until tcpdump has exited
	sniffer.cancel()
	if err := <-sniffer.exited; err != nil {
		a.Fatalf("Failed to execute tcpdump: %w", err)
	}

	// Redirect stderr to /dev/null, as tcpdump logs to stderr, and ExecInPod
	// will return an error if any char is written to stderr. Anyway, the count
	// is written to stdout.
	cmd := []string{"/bin/sh", "-c", fmt.Sprintf("tcpdump -r %s --count 2>/dev/null", sniffer.dumpPath)}
	count, err := sniffer.host.K8sClient.ExecInPod(ctx, sniffer.host.Pod.Namespace, sniffer.host.Pod.Name, "", cmd)
	if err != nil {
		a.Fatalf("Failed to retrieve tcpdump pkt count: %s", err)
	}

	if !strings.Contains(count.String(), "packet") {
		a.Fatalf("tcpdump output doesn't look correct: %s", count.String())
	}

	if !strings.HasPrefix(count.String(), "0 packets") && assertNoLeaks {
		a.Failf("Captured unencrypted pkt (count=%s)", strings.TrimRight(count.String(), "\n\r"))

		// If debug mode is enabled, dump the captured pkts
		if debug {
			cmd := []string{"/bin/sh", "-c", fmt.Sprintf("tcpdump -r %s 2>/dev/null", sniffer.dumpPath)}
			out, err := sniffer.host.K8sClient.ExecInPod(ctx, sniffer.host.Pod.Namespace, sniffer.host.Pod.Name, "", cmd)
			if err != nil {
				a.Fatalf("Failed to retrieve tcpdump output: %s", err)
			}
			a.Debugf("Captured pkts:\n%s", out.String())
		}
	}

	if strings.HasPrefix(count.String(), "0 packets") && !assertNoLeaks {
		a.Failf("Expected to see unencrypted packets, but none found. This check might be broken")
	}
}
