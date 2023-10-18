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
//
// For WireGuard w/ tunneling we run the cmd with $DST_IP set to serverHost IP.
// We cannot listen on the tunneling netdev, because the datapath first passes
// a packet to the tunnel netdev, and only afterwards redirects to the WG netdev
// for the encryption.
func getInterNodeIface(ctx context.Context, t *check.Test,
	client, clientHost, server, serverHost *check.Pod, ipFam features.IPFamily) string {

	tunnelEnabled := false
	tunnelMode := ""
	if tunnelFeat, ok := t.Context().Feature(features.Tunnel); ok && tunnelFeat.Enabled {
		tunnelEnabled = true
		tunnelMode = tunnelFeat.Mode
	}

	srcIP, dstIP := client.Address(ipFam), server.Address(ipFam)
	ipRouteGetCmd := fmt.Sprintf("ip -o route get %s from %s", dstIP, srcIP)
	if srcIP != clientHost.Address(ipFam) {
		// The "iif lo" part is required when the source address is not one
		// of the addresses of the host. If an interface is not specified
		// "ip route" returns "RTNETLINK answers: Network is unreachable" in
		// case the "from" address is not assigned to any local interface.
		ipRouteGetCmd = fmt.Sprintf("%s iif lo", ipRouteGetCmd)
	}

	// TODO(brb) version check
	// The WG w/ tunnel case:
	if enc, ok := t.Context().Feature(features.EncryptionPod); ok && enc.Enabled && enc.Mode == "wireguard" {
		ipRouteGetCmd = fmt.Sprintf("ip -o route get %s", serverHost.Address(ipFam))
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

	if tunnelEnabled {
		// When tunneling is enabled, and the traffic is routed to the cilium IP space
		// we want to capture on the tunnel interface.
		if device == defaults.HostDevice {
			return "cilium_" + tunnelMode // E.g. cilium_vxlan
		}

		// When both tunneling and host firewall is enabled, traffic from a pod
		// to a remote nodes gets forwarded through the tunnel to preserve the
		// source identity.
		if hf, ok := t.Context().Feature(features.HostFirewall); ok && hf.Enabled &&
			clientHost.Address(ipFam) != srcIP {
			return "cilium_" + tunnelMode // E.g. cilium_vxlan
		}
	}

	return device
}

// getFilter constructs a tcpdump filter to capture leakages of unencrypted pkts.
//
// The exact filter depends on the routing mode and some features. The common
// structure is "src host $SRC_IP and dst host $DST_IP and $PROTO".
//
// WireGuard w/ tunnel: this is a special case. We are interested to see whether
// any unencrypted VXLAN pkt is leaked on a native device.
func getFilter(ctx context.Context, t *check.Test, client, clientHost *check.Pod,
	server, serverHost *check.Pod,
	ipFam features.IPFamily, reqType requestType) string {

	tunnelEnabled := false
	if tunnelStatus, ok := t.Context().Feature(features.Tunnel); ok && tunnelStatus.Enabled {
		tunnelEnabled = true
	}

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

	if enc, ok := t.Context().Feature(features.EncryptionPod); tunnelEnabled && ok &&
		enc.Enabled && enc.Mode == "wireguard" {

		// Captures the following:
		// - Any VXLAN/Geneve pkt client host <-> server host. Such a pkt might
		//   contain a leaked pod-to-pod unencrypted pkt. We could have made this
		//   filter more fine-grained (i.e., to filter an inner pkt), but that
		//   requires nasty filtering based on UDP offsets (pcap-filter doesn't
		//   filtering of VXLAN/Geneve inner layers).
		// - Any pkt client <-> server with a given proto. This might be useful
		//   to catch any regression in the DP which makes the pkt to bypass
		//   the VXLAN tunnel.
		//
		// Some explanations:
		// - "udp[8:2] = 0x0800" compares the first two bytes of an UDP payload
		//   against VXLAN commonly used flags. In addition we check against
		//   the default Cilium's VXLAN port (8472).
		// - To catch Geneve traffic we cannot use the "geneve" filter, as it shifts
		//   offset of a filted packet which invalidates the later part of the
		//   filter. Thus this poor UDP/6081 check.
		tunnelFilter := "(udp and (udp[8:2] = 0x0800 or dst port 8472 or dst 6081))"
		filter := fmt.Sprintf("(%s and host %s and host %s) or (host %s and host %s and %s)",
			tunnelFilter,
			clientHost.Address(features.IPFamilyV4), serverHost.Address(features.IPFamilyV4),
			client.Address(ipFam), server.Address(ipFam), protoFilter)

		return filter

	}

	filter := fmt.Sprintf("src host %s", client.Address(ipFam))
	dstIP := server.Address(ipFam)

	if tunnelStatus, ok := t.Context().Feature(features.Tunnel); ok && tunnelStatus.Enabled {
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
	}

	filter = fmt.Sprintf("%s and %s", filter, protoFilter)

	// Unfortunately, we cannot use "host %s and host %s" filter here,
	// as IPsec recirculates replies to the iface netdev, which would
	// make tcpdump to capture the pkts (false positive).
	filter = fmt.Sprintf("%s and dst host %s", filter, dstIP)

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
		testNoTrafficLeak(ctx, t, s, client, &server, &clientHost, &serverHost, requestHTTP, ipFam, assertNoLeaks, true)
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
	client, server, clientHost *check.Pod, serverHost *check.Pod,
	reqType requestType, ipFam features.IPFamily, assertNoLeaks, biDirCheck bool,
) {
	srcFilter := getFilter(ctx, t, client, clientHost, server, serverHost, ipFam, reqType)
	srcIface := getInterNodeIface(ctx, t, client, clientHost, server, serverHost, ipFam)

	srcSniffer, err := startLeakSniffer(ctx, t, clientHost, srcIface, srcFilter)
	if err != nil {
		t.Fatal(err)
	}

	var dstSniffer *leakSniffer
	if biDirCheck {
		dstFilter := getFilter(ctx, t, server, serverHost, client, clientHost, ipFam, reqType)
		dstIface := getInterNodeIface(ctx, t, server, serverHost, client, clientHost, ipFam)

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
		podToPodWGWithTunnel := false
		if e, ok := t.Context().Feature(features.EncryptionPod); ok && e.Enabled && e.Mode == "wireguard" {
			if n, ok := t.Context().Feature(features.EncryptionNode); ok && !n.Enabled {
				if t, ok := t.Context().Feature(features.Tunnel); ok && t.Enabled {
					podToPodWGWithTunnel = true
				}
			}
		}
		// Test pod-to-remote-host (ICMP Echo instead of HTTP because a remote host
		// does not have a HTTP server running)
		if !podToPodWGWithTunnel {
			// In tunnel case ignore this check which expects unencrypted pkts.
			// The filter built for this check doesn't take into account that
			// pod-to-remote-node is SNAT-ed. Thus 'host $SRC_HOST and host $DST_HOST and icmp'
			// doesn't catch any pkt.
			testNoTrafficLeak(ctx, t, s, client, &serverHost, &clientHost, &serverHost, requestICMPEcho, ipFam, assertNoLeaks, false)
		}
		// Test host-to-remote-host
		testNoTrafficLeak(ctx, t, s, &clientHost, &serverHost, &clientHost, &serverHost, requestICMPEcho, ipFam, assertNoLeaks, true)
		// Test host-to-remote-pod (going to be encrypted with WG pod-to-pod + tunnel)
		hostToPodAssertNoLeaks := assertNoLeaks
		if podToPodWGWithTunnel {
			hostToPodAssertNoLeaks = true
		}
		testNoTrafficLeak(ctx, t, s, &clientHost, &server, &clientHost, &serverHost, requestHTTP, ipFam, hostToPodAssertNoLeaks, false)
	})
}
