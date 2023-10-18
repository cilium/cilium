// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/defaults"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

type requestType int

const (
	requestHTTP requestType = iota
	requestICMPEcho
)

// getInterNodeIface determines on which netdev iface to capture pkts.
// We run "ip route get $DST_IP" from the client pod's node to see to
// which interface the traffic is routed to. Additionally, we translate
// the interface name to the tunneling interface name, if the route goes
// through "cilium_host" and tunneling is enabled.
func getInterNodeIface(ctx context.Context, t *check.Test, clientHost *check.Pod, ipFam features.IPFamily, srcIP, dstIP string) string {
	ipRouteGetCmd := fmt.Sprintf("ip -o route get %s from %s", dstIP, srcIP)
	if srcIP != clientHost.Address(ipFam) {
		// The "iif lo" part is required when the source address is not one
		// of the addresses of the host. If an interface is not specified
		// "ip route" returns "RTNETLINK answers: Network is unreachable" in
		// case the "from" address is not assigned to any local interface.
		ipRouteGetCmd = fmt.Sprintf("%s iif lo", ipRouteGetCmd)
	}

	cmd := []string{
		"/bin/sh", "-c",
		fmt.Sprintf("%s | grep -oE 'dev [^ ]*' | cut -d' ' -f2", ipRouteGetCmd),
	}
	t.Debugf("Running %s", strings.Join(cmd, " "))
	dev, err := clientHost.K8sClient.ExecInPod(ctx, clientHost.Pod.Namespace,
		clientHost.Pod.Name, "", cmd)
	if err != nil {
		t.Fatalf("Failed to get IP route: %s", err)
	}

	device := strings.TrimRight(dev.String(), "\n\r")

	if tunnelFeat, ok := t.Context().Feature(features.Tunnel); ok && tunnelFeat.Enabled {
		// When tunneling is enabled, and the traffic is routed to the cilium IP space
		// we want to capture on the tunnel interface.
		if device == defaults.HostDevice {
			return "cilium_" + tunnelFeat.Mode // E.g. cilium_vxlan
		}

		// When both tunneling and host firewall is enabled, traffic from a pod
		// to a remote nodes gets forwarded through the tunnel to preserve the
		// source identity.
		if hf, ok := t.Context().Feature(features.HostFirewall); ok && hf.Enabled &&
			clientHost.Address(ipFam) != srcIP {
			return "cilium_" + tunnelFeat.Mode // E.g. cilium_vxlan
		}
	}

	return device
}

// getFilter constructs the source IP address filter we want to use for
// capturing packet. If direct routing is used, the source IP is the client IP,
// otherwise, either the client IP or the one associated with the egressing interface.
func getFilter(ctx context.Context, t *check.Test, client,
	clientHost *check.Pod, ipFam features.IPFamily, dstIP string,
) string {
	filter := fmt.Sprintf("src host %s", client.Address(ipFam))
	if tunnelStatus, ok := t.Context().Feature(features.Tunnel); ok &&
		!tunnelStatus.Enabled {
		return filter
	}

	cmd := []string{
		"/bin/sh", "-c",
		fmt.Sprintf("ip -o route get %s | grep -oE 'src [^ ]*' | cut -d' ' -f2",
			dstIP),
	}
	t.Debugf("Running %s", strings.Join(cmd, " "))
	srcIP, err := clientHost.K8sClient.ExecInPod(ctx, clientHost.Pod.Namespace,
		clientHost.Pod.Name, "", cmd)
	if err != nil {
		t.Fatalf("Failed to get IP route: %s", err)
	}

	srcIPStr := strings.TrimRight(srcIP.String(), "\n\r")
	if srcIPStr != client.Address(ipFam) {
		filter = fmt.Sprintf("( %s or src host %s )", filter, srcIPStr)
	}
	return filter
}

// PodToPodEncryption is a test case which checks the following:
//   - There is a connectivity between pods on different nodes when any
//     encryption mode is on (either WireGuard or IPsec).
//   - No unencrypted packet is leaked. As a sanity check, we additionally
//     run the same test also when encryption is disabled, asserting that
//     we effectively observe unencrypted packets.
//
// The checks are implemented by curl'ing a server pod from a client pod, and
// then inspecting tcpdump captures from the client pod's node.
func PodToPodEncryption(reqs ...features.Requirement) check.Scenario {
	return &podToPodEncryption{reqs}
}

type podToPodEncryption struct{ reqs []features.Requirement }

func (s *podToPodEncryption) Name() string {
	return "pod-to-pod-encryption"
}

func (s *podToPodEncryption) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	client := ct.RandomClientPod()

	var server check.Pod
	for _, pod := range ct.EchoPods() {
		// Make sure that the server pod is on another node than client
		if pod.Pod.Status.HostIP != client.Pod.Status.HostIP {
			server = pod
			break
		}
	}

	// clientHost is a pod running on the same node as the client pod, just in
	// the host netns.
	clientHost := ct.HostNetNSPodsByNode()[client.Pod.Spec.NodeName]
	// serverHost is a pod running in a remote node's host netns.
	serverHost := t.Context().HostNetNSPodsByNode()[server.Pod.Spec.NodeName]
	assertNoLeaks, _ := ct.Features.MatchRequirements(s.reqs...)

	if !assertNoLeaks {
		t.Debugf("%s test running in sanity mode, expecting unencrypted packets", s.Name())
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		testNoTrafficLeak(ctx, t, s, client, &server, &clientHost, &serverHost, requestHTTP, ipFam, assertNoLeaks)
	})
}

type leakSniffer struct {
	host     *check.Pod
	dumpPath string

	stdout safeBuffer
	cancel context.CancelFunc
	exited chan error
}

func startLeakSniffer(ctx context.Context, t *check.Test, host *check.Pod,
	iface string, filter string,
) (*leakSniffer, error) {
	cmdctx, cancel := context.WithCancel(ctx)
	sniffer := &leakSniffer{
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

func (sniffer *leakSniffer) validate(ctx context.Context, a *check.Action, assertNoLeaks, debug bool) {
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

func testNoTrafficLeak(ctx context.Context, t *check.Test, s check.Scenario,
	client, server, clientHost *check.Pod, serverHost *check.Pod, /* serverHost=nil disables the bidirectional check */
	reqType requestType, ipFam features.IPFamily, assertNoLeaks bool,
) {
	protoFilter := ""
	switch reqType {
	case requestHTTP:
		protoFilter = "tcp"
	case requestICMPEcho:
		protoFilter = "icmp"
		if ipFam == features.IPFamilyV6 {
			protoFilter = "icmp6"
		}
	default:
		t.Fatalf("Invalid request type: %d", reqType)
	}

	srcAddr, dstAddr := client.Address(ipFam), server.Address(ipFam)
	srcAddrFilter := getFilter(ctx, t, client, clientHost, ipFam, dstAddr)
	srcIface := getInterNodeIface(ctx, t, clientHost, ipFam, client.Address(ipFam), dstAddr)

	// Capture egress traffic.
	// Unfortunately, we cannot use "host %s and host %s" filter here,
	// as IPsec recirculates replies to the iface netdev, which would
	// make tcpdump to capture the pkts (false positive).
	srcFilter := fmt.Sprintf("%s and dst host %s and %s", srcAddrFilter, dstAddr, protoFilter)

	srcSniffer, err := startLeakSniffer(ctx, t, clientHost, srcIface, srcFilter)
	if err != nil {
		t.Fatal(err)
	}

	var dstSniffer *leakSniffer
	if serverHost != nil {
		dstAddrFilter := strings.ReplaceAll(srcAddrFilter, "src", "dst")
		dstIface := getInterNodeIface(ctx, t, serverHost, ipFam, server.Address(ipFam), srcAddr)
		dstFilter := fmt.Sprintf("src host %s and %s and %s", dstAddr, dstAddrFilter, protoFilter)

		dstSniffer, err = startLeakSniffer(ctx, t, serverHost, dstIface, dstFilter)
		if err != nil {
			t.Fatal(err)
		}
	}

	switch reqType {
	case requestHTTP:
		// Curl the server from the client to generate some traffic
		t.NewAction(s, fmt.Sprintf("curl-%s", ipFam), client, server, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, t.Context().CurlCommand(server, ipFam))
			srcSniffer.validate(ctx, a, assertNoLeaks, t.Context().Params().Debug)
			if dstSniffer != nil {
				dstSniffer.validate(ctx, a, assertNoLeaks, t.Context().Params().Debug)
			}
		})
	case requestICMPEcho:
		// Ping the server from the client to generate some traffic
		t.NewAction(s, fmt.Sprintf("ping-%s", ipFam), client, server, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, t.Context().PingCommand(server, ipFam))
			srcSniffer.validate(ctx, a, assertNoLeaks, t.Context().Params().Debug)
			if dstSniffer != nil {
				dstSniffer.validate(ctx, a, assertNoLeaks, t.Context().Params().Debug)
			}
		})
	}
}

// bytes.Buffer from the stdlib is non-thread safe, thus our custom
// implementation. Unfortunately, we cannot use io.Pipe, as Write() blocks until
// Read() has read all content, which makes it deadlock-prone when used with
// ExecInPodWithWriters() running in a separate goroutine.
type safeBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *safeBuffer) Read(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Read(p)
}

func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Write(p)
}

func (b *safeBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.b.String()
}

func (b *safeBuffer) ReadString(d byte) (string, error) {
	b.Lock()
	defer b.Unlock()
	return b.b.ReadString(d)
}

func NodeToNodeEncryption(reqs ...features.Requirement) check.Scenario {
	return &nodeToNodeEncryption{reqs}
}

type nodeToNodeEncryption struct{ reqs []features.Requirement }

func (s *nodeToNodeEncryption) Name() string {
	return "node-to-node-encryption"
}

func (s *nodeToNodeEncryption) Run(ctx context.Context, t *check.Test) {
	client := t.Context().RandomClientPod()

	var server check.Pod
	for _, pod := range t.Context().EchoPods() {
		// Make sure that the server pod is on another node than client
		if pod.Pod.Status.HostIP != client.Pod.Status.HostIP {
			server = pod
			break
		}
	}

	// clientHost is a pod running on the same node as the client pod, just in
	// the host netns.
	clientHost := t.Context().HostNetNSPodsByNode()[client.Pod.Spec.NodeName]
	// serverHost is a pod running in a remote node's host netns.
	serverHost := t.Context().HostNetNSPodsByNode()[server.Pod.Spec.NodeName]
	assertNoLeaks, _ := t.Context().Features.MatchRequirements(s.reqs...)

	if !assertNoLeaks {
		t.Debugf("%s test running in sanity mode, expecting unencrypted packets", s.Name())
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		// Test pod-to-remote-host (ICMP Echo instead of HTTP because a remote host
		// does not have a HTTP server running)
		testNoTrafficLeak(ctx, t, s, client, &serverHost, &clientHost, nil, requestICMPEcho, ipFam, assertNoLeaks)
		// Test host-to-remote-host
		testNoTrafficLeak(ctx, t, s, &clientHost, &serverHost, &clientHost, nil, requestICMPEcho, ipFam, assertNoLeaks)
		// Test host-to-remote-pod
		testNoTrafficLeak(ctx, t, s, &clientHost, &server, &clientHost, nil, requestHTTP, ipFam, assertNoLeaks)
	})
}
