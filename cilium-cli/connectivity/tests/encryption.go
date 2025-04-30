// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/defaults"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/versioncheck"
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
	client, clientHost, server, serverHost *check.Pod, ipFam features.IPFamily,
	wgEncap bool) string {

	tunnelEnabled := false
	tunnelMode := ""
	if tunnelFeat, ok := t.Context().Feature(features.Tunnel); ok && tunnelFeat.Enabled {
		tunnelEnabled = true
		tunnelMode = tunnelFeat.Mode
	}

	srcIP, dstIP := client.Address(ipFam), server.Address(ipFam)
	ipRouteGetCmd := fmt.Sprintf("ip -o route get %s from %s", dstIP, srcIP)
	if srcIP != clientHost.Address(ipFam) {
		// The "iif cilium_host" part is required when the source address is not
		// one of the addresses of the host. If an interface is not specified
		// "ip route" returns "RTNETLINK answers: Network is unreachable" in
		// case the "from" address is not assigned to any local interface.
		// Any existing interface name works, as long as the corresponding
		// rp_filter value is different from 1, i.e., strict (otherwise it
		// returns "RTNETLINK answers: Invalid cross-device link"). For this
		// reason, let's use one of the interfaces managed by Cilium, as we
		// explicitly set rp_filter=0 for them.
		ipRouteGetCmd = fmt.Sprintf("%s iif cilium_host", ipRouteGetCmd)
	}

	if enc, ok := t.Context().Feature(features.EncryptionPod); wgEncap && ok && enc.Enabled && enc.Mode == "wireguard" {
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

	if tunnelEnabled && !wgEncap {
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
	ipFam features.IPFamily, reqType requestType, wgEncap bool) string {

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

	if enc, ok := t.Context().Feature(features.EncryptionPod); wgEncap && tunnelEnabled && ok &&
		enc.Enabled && enc.Mode == "wireguard" {
		tunnelFilter, err := sniff.GetTunnelFilter(t.Context())
		if err != nil {
			t.Fatalf("Failed to build tunnel filter: %w", err)
		}

		// Captures the following:
		// - Any VXLAN/Geneve pkt client host <-> server host. Such a pkt might
		//   contain a leaked pod-to-pod unencrypted pkt. We could have made this
		//   filter more fine-grained (i.e., to filter an inner pkt), but that
		//   requires nasty filtering based on UDP offsets (pcap-filter doesn't
		//   filtering of VXLAN/Geneve inner layers).
		// - Any pkt client <-> server with a given proto. This might be useful
		//   to catch any regression in the DP which makes the pkt to bypass
		//   the VXLAN tunnel.
		filter := fmt.Sprintf("((%s and host %s and host %s) or (host %s and host %s and %s))",
			tunnelFilter,
			clientHost.Address(features.IPFamilyV4), serverHost.Address(features.IPFamilyV4),
			client.Address(ipFam), server.Address(ipFam), protoFilter)

		// Exclude icmpv6 neighbor broadcast packets, as these are intentionally not encrypted:
		// Ref[0]: https://github.com/cilium/cilium/blob/e8543eef/bpf/lib/wireguard.h#L95
		// See Issue: #38688
		filter = fmt.Sprintf("(%s) and (%s)", filter, icmpv6NAFilter)

		return filter

	}

	filter := fmt.Sprintf("src host %s", client.Address(ipFam))
	dstIP := server.Address(ipFam)

	if tunnelEnabled {
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

	// Exclude icmpv6 neighbor broadcast packets, as these are intentionally not encrypted:
	// Ref[0]: https://github.com/cilium/cilium/blob/e8543eef/bpf/lib/wireguard.h#L95
	// See Issue: #38688
	filter = fmt.Sprintf("(%s) and (%s)", filter, icmpv6NAFilter)

	return filter
}

// isWgEncap checks whether packets are encapsulated before encrypting with WG.
//
// In v1.14, it's an opt-in, and controlled by --wireguard-encapsulate.
// In v1.15, it's enabled, and it's not possible to opt-out.
func isWgEncap(t *check.Test) bool {
	if e, ok := t.Context().Feature(features.EncryptionPod); !(ok && e.Enabled && e.Mode == "wireguard") {
		return false
	}
	if t, ok := t.Context().Feature(features.Tunnel); !(ok && t.Enabled) {
		return false
	}
	if versioncheck.MustCompile(">=1.15.0")(t.Context().CiliumVersion) {
		return true
	}
	if encap, ok := t.Context().Feature(features.WireguardEncapsulate); !(ok && encap.Enabled) {
		return false
	}

	return true
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
	return &podToPodEncryption{
		reqs:         reqs,
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToPodEncryption struct {
	check.ScenarioBase

	reqs []features.Requirement
}

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

	wgEncap := isWgEncap(t)
	if wgEncap {
		t.Debug("Encapsulation before WG encryption")
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		testNoTrafficLeak(ctx, t, s, client, &server, &clientHost, &serverHost, requestHTTP, ipFam, assertNoLeaks, true, wgEncap)
	})
}

func testNoTrafficLeak(ctx context.Context, t *check.Test, s check.Scenario,
	client, server, clientHost *check.Pod, serverHost *check.Pod,
	reqType requestType, ipFam features.IPFamily, assertNoLeaks, biDirCheck, wgEncap bool,
) {
	srcFilter := getFilter(ctx, t, client, clientHost, server, serverHost, ipFam, reqType, wgEncap)
	srcIface := getInterNodeIface(ctx, t, client, clientHost, server, serverHost, ipFam, wgEncap)

	snifferMode := sniff.ModeAssert
	if !assertNoLeaks {
		snifferMode = sniff.ModeSanity
	}

	srcSniffer, err := sniff.Sniff(ctx, s.Name(), clientHost, srcIface, srcFilter, snifferMode, t)
	if err != nil {
		t.Fatal(err)
	}

	var dstSniffer *sniff.Sniffer
	if biDirCheck {
		dstFilter := getFilter(ctx, t, server, serverHost, client, clientHost, ipFam, reqType, wgEncap)
		dstIface := getInterNodeIface(ctx, t, server, serverHost, client, clientHost, ipFam, wgEncap)

		dstSniffer, err = sniff.Sniff(ctx, s.Name(), serverHost, dstIface, dstFilter, snifferMode, t)
		if err != nil {
			t.Fatal(err)
		}
	}

	switch reqType {
	case requestHTTP:
		// Curl the server from the client to generate some traffic
		t.NewAction(s, fmt.Sprintf("curl-%s", ipFam), client, server, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, a.CurlCommand(server))
			srcSniffer.Validate(ctx, a)
			if dstSniffer != nil {
				dstSniffer.Validate(ctx, a)
			}
		})
	case requestICMPEcho:
		// Ping the server from the client to generate some traffic
		t.NewAction(s, fmt.Sprintf("ping-%s", ipFam), client, server, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, t.Context().PingCommand(server, ipFam))
			srcSniffer.Validate(ctx, a)
			if dstSniffer != nil {
				dstSniffer.Validate(ctx, a)
			}
		})
	}
}

func nodeToNodeEncTestPods(nodes map[check.NodeIdentity]*ciliumv2.CiliumNode, excludeSelector labels.Selector, clients, servers []check.Pod) (client, server *check.Pod) {
	nodeKey := func(pod *check.Pod) check.NodeIdentity {
		if pod != nil {
			return check.NodeIdentity{Cluster: pod.K8sClient.ClusterName(), Name: pod.NodeName()}
		}
		return check.NodeIdentity{}
	}

	acceptableNodes := func(pods []check.Pod) sets.Set[check.NodeIdentity] {
		keys := sets.New[check.NodeIdentity]()
		for _, pod := range pods {
			node := nodes[nodeKey(&pod)]
			if node == nil {
				continue
			}

			if excludeSelector.Matches(labels.Set(node.Labels)) {
				continue
			}

			keys.Insert(nodeKey(&pod))
		}
		return keys
	}

	getRandomPod := func(pods []check.Pod, nodes sets.Set[check.NodeIdentity]) *check.Pod {
		for _, pod := range pods {
			if nodes.Has(nodeKey(&pod)) {
				return &pod
			}
		}

		return nil
	}

	clientNodes := acceptableNodes(clients)
	serverNodes := acceptableNodes(servers)

	// Prefer selecting a client (server) running on a node which does not
	// host a server (client) as well, to maximize the possibilities of finding
	// a valid combination.
	clientNodesOnly := clientNodes.Difference(serverNodes)
	serverNodesOnly := serverNodes.Difference(clientNodes)

	client = getRandomPod(clients, clientNodesOnly)
	if client == nil {
		client = getRandomPod(clients, clientNodes)
	}

	server = getRandomPod(servers, serverNodesOnly)
	if server == nil {
		// Make sure to not pick a server hosted on the same node of the client.
		serverNodes.Delete(nodeKey(client))
		server = getRandomPod(servers, serverNodes)
	}

	return client, server
}

func NodeToNodeEncryption(reqs ...features.Requirement) check.Scenario {
	return &nodeToNodeEncryption{
		reqs:         reqs,
		ScenarioBase: check.NewScenarioBase(),
	}
}

type nodeToNodeEncryption struct {
	check.ScenarioBase

	reqs []features.Requirement
}

func (s *nodeToNodeEncryption) Name() string {
	return "node-to-node-encryption"
}

func (s *nodeToNodeEncryption) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	encryptNode, _ := ct.Feature(features.EncryptionNode)

	// Node to node encryption can be disabled on specific nodes (e.g.,
	// control plane ones) to prevent e.g., losing connectivity to the
	// Kubernetes API Server. Let's take that into account when selecting
	// the target pods/nodes.
	excludeNodes := labels.Nothing()
	if encryptNode.Enabled {
		var err error
		if excludeNodes, err = labels.Parse(encryptNode.Mode); err != nil {
			t.Fatalf("unable to parse label selector %s: %s", encryptNode.Mode, err)
		}
	}

	client, server := nodeToNodeEncTestPods(ct.CiliumNodes(), excludeNodes,
		slices.Collect(maps.Values(ct.ClientPods())),
		slices.Collect(maps.Values(ct.EchoPods())))
	if client == nil || server == nil {
		t.Fatal("Could not find matching pods: is node to node encryption disabled on all nodes hosting test pods?")
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

	wgEncap := isWgEncap(t)
	if wgEncap {
		t.Debug("Encapsulation before WG encryption")
	}
	onlyPodToPodWGWithTunnel := false
	if wgEncap {
		if n, ok := t.Context().Feature(features.EncryptionNode); ok && !n.Enabled {
			onlyPodToPodWGWithTunnel = true
		}
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {

		// Test pod-to-remote-host (ICMP Echo instead of HTTP because a remote host
		// does not have a HTTP server running)
		if !onlyPodToPodWGWithTunnel {
			// In tunnel case ignore this check which expects unencrypted pkts.
			// The filter built for this check doesn't take into account that
			// pod-to-remote-node is SNAT-ed. Thus 'host $SRC_HOST and host $DST_HOST and icmp'
			// doesn't catch any pkt.
			testNoTrafficLeak(ctx, t, s, client, &serverHost, &clientHost, &serverHost, requestICMPEcho, ipFam, assertNoLeaks, false, wgEncap)
		}
		// Test host-to-remote-host
		testNoTrafficLeak(ctx, t, s, &clientHost, &serverHost, &clientHost, &serverHost, requestICMPEcho, ipFam, assertNoLeaks, true, wgEncap)
		// Test host-to-remote-pod (going to be encrypted with WG pod-to-pod + tunnel)
		hostToPodAssertNoLeaks := assertNoLeaks
		if onlyPodToPodWGWithTunnel {
			hostToPodAssertNoLeaks = true
		}
		testNoTrafficLeak(ctx, t, s, &clientHost, server, &clientHost, &serverHost, requestHTTP, ipFam, hostToPodAssertNoLeaks, false, wgEncap)
	})
}
