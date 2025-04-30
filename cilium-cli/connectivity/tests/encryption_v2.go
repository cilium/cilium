// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

var _ check.Scenario = (*podToPodEncryptionV2)(nil)

// PodToPodEncryptionV2 is a test which ensures client traffic to a server pod
// is encrypted and not leaked.
//
// This tests runs on clusters post v1.18 which requires both IPsec and Wireguard
// to utilize encrypted overlay, where encryption occurs just prior to the
// final egress of a pod-to-pod packet.
//
// In tunnel mode this means VXLAN|GENEVE encap happens prior to encryption and the
// tunnel encap'd packet is further encapsulated into IPsec's ESP tunnel headers.
//
// The actual test scenario can focus on the egress device for a pod-to-pod flow.
// The egress device is the final interface where the encrypted packet is xmitted
// on to reach the wire and head toward the destination.
//
// On this egress device (typically eth0 in the host network namespace) TCPDUMP
// is used to capture packets.
//
// In native routing mode the TCPDUMP filter simply looks for plain text pod
// to pod traffic for the client and server pods under test.
//
// For tunnel mode the TCPDUMP filter looks for UDP packets which match:
// 1. UDP protocol
// 2. UDP port matching the configured tunnel mode's current port
// 3. Inner IP headers of pod-to-pod traffic.
// In other words the TCPDUMP filter seeks into the tunnel packet and looks for
// plain-text pod-to-pod traffic for the client and server pods under test.
//
// Leak detection is performed both on the client side and server side, ensuring
// client->server traffic is encrypted and the return traffic, server->client
// is encrypted as well.
//
// This test should be ran both when encryption is enabled AND disabled.
//
// When encryption is enabled the test will check that no packets match the
// TCPDUMP filter, i.e. there are no plain text leaks
//
// When encryption is disabled the test will check that packets DO match the
// TCPDUMP filter, this is a sanity check to ensure we match plain-text packets
// appropriately and have confidence that aforementioned leak detection works.
func PodToPodEncryptionV2() check.Scenario {
	return &podToPodEncryptionV2{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToPodEncryptionV2 struct {
	check.ScenarioBase

	ct *check.ConnectivityTest
	// client pod used to generate traffic
	client *check.Pod
	// server pod which receives and responds to client traffic
	server *check.Pod
	// pod on client's node providing access to host network namespace
	clientHostNS *check.Pod
	// pod on server's node providing access to host network namespace
	serverHostNS *check.Pod

	tunnelMode  features.Status
	encryptMode features.Status
	ipv4Enabled features.Status
	ipv6Enabled features.Status

	// the egress device, on the client node, that client->server traffic will
	// leave on.
	//
	// NOTE: this test assumes that if IPv6 is enabled the same egress device
	// is used to push client traffic toward the server.
	// this will almost always be the case.
	clientEgressDev string
	// the egress device, on the server node, that server->client (return traffic)
	// will leave on.
	//
	// see clientEgressDev NOTE:
	serverEgressDev string

	// pcap filter used to detect leaks on the client side
	clientFilter4 string
	// pcap filter used to detect leaks on the server side
	serverFilter4 string
	// tcpdump running on the client
	clientSniffer4 *sniff.Sniffer
	// tcpdump running on the server
	serverSniffer4 *sniff.Sniffer

	// IPv6 variants of the above
	clientFilter6  string
	serverFilter6  string
	clientSniffer6 *sniff.Sniffer
	serverSniffer6 *sniff.Sniffer
}

func (s *podToPodEncryptionV2) Name() string {
	return "pod-to-pod-encryption-v2"
}

// resolveEgressDevice resolves the egress device used in the provided host
// network namespace used to send traffic to dst.
func (s *podToPodEncryptionV2) resolveEgressDevice(ctx context.Context, srcHostNS *check.Pod, src, dst *check.Pod) (string, error) {
	// if tunnel encap is used, the packet will be encapsulated before
	// leaving the host, thus, use the tunnel endpoint IP rather then the
	// pod IP for route lookup.
	var srcIP, dstIP string
	if s.tunnelMode.Enabled {
		srcIP = src.Pod.Status.HostIP
		dstIP = dst.Pod.Status.HostIP
	} else {
		srcIP = src.Pod.Status.PodIP
		dstIP = dst.Pod.Status.PodIP
	}

	// issue `ip route get dstIP from srcIP iif cilium_host` for destination in provided
	// host network namespace and extract device.

	// the `from srcIP` part is needed to tackle cases such as awscni, where there is a
	// dedicated routing table (using != egress device) for traffic with that srcIP.
	// the `from srcIP` is ignored in case it doesn't match any non-default route.
	// the `iif cilium_host` parameter is needed to return anything useful from the command,
	// but it is ignored if `ip rules` do not have an interface specified in the rule.
	//
	// example json output:
	// [{"dst":"192.168.109.96","gateway":"192.168.128.1","dev":"ens5","prefsrc":"192.168.159.49","flags":[],"uid":0,"cache":[]}]
	out, err := srcHostNS.K8sClient.ExecInPod(ctx,
		srcHostNS.Pod.Namespace,
		srcHostNS.Pod.Name,
		"",
		[]string{"ip", "-j", "route", "get", dstIP, "from", srcIP, "iif", "cilium_host"})

	if err != nil {
		return "", fmt.Errorf("Failed to resolve egress device for: %w", err)
	}

	routes := []struct {
		Dev string `json:"dev,omitempty"`
	}{}

	err = json.Unmarshal(out.Bytes(), &routes)
	if err != nil {
		return "", fmt.Errorf("Failed to parse ip route to json: %w", err)
	}

	// search for dev key in ip route output.
	for _, route := range routes {
		if route.Dev != "" {
			return route.Dev, nil
		}
	}

	return "", fmt.Errorf("Failed to find egress device")
}

// resolveClientEgressDevice determines the ultimate egress device used to
// send a client's packet to the link-local network and toward the destination.
//
// in native routing mode this will be an "ip route get {dst_pod_ip}" while in
// tunnel mode this will be "ip route get {dst_node_ip}" as the packet will be
// tunnel encap'd before departure.
func (s *podToPodEncryptionV2) resolveClientEgressDevice(ctx context.Context) (string, error) {
	// we have a context, may as well check it
	if ctx.Err() != nil {
		return "", fmt.Errorf("Context already cancelled")
	}

	return s.resolveEgressDevice(ctx, s.clientHostNS, s.client, s.server)
}

// resolveServerEgressDevice is the similar to resolveClientEgressDevice but
// finds the egress device for client return traffic from the server.
func (s *podToPodEncryptionV2) resolveServerEgressDevice(ctx context.Context) (string, error) {
	// we have a context, may as well check it
	if ctx.Err() != nil {
		return "", fmt.Errorf("Context already cancelled")
	}
	return s.resolveEgressDevice(ctx, s.serverHostNS, s.server, s.client)
}

// tunnelTCPDumpFilters4 will generate the required TCPDump filters for leak
// detection when the cluster is in tunnel routing mode.
//
// the TCPDump filter will:
//  1. detect UDP traffic
//  2. detect that the UDP dst port is the configured tunnel protocol port
//  3. seek into the VXLAN|GENEVE packet and ensure the IP header does not contain
//     [src: client, dst: server], this would be a leak.
func (s *podToPodEncryptionV2) tunnelTCPDumpFilters4(ctx context.Context) (clientFilter string, serverFilter string, err error) {
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("Context already cancelled")
	}

	// Start at the UDP header (VXLAN|GENEVE) and index into IPHeader.Src and IPHeader.Dst
	// UDP(8)+VXLAN|GENEVE(8)+ETHER(14) = udp[30] + Offset to IPHeader.Src = udp[42]
	// UDP(8)+VXLAN|GENEVE(8)+ETHER(14) = udp[30] + Offset to IPHeader.Dst = udp[46]
	fmtInnerIPHeaderSrc := "udp[42:4] == %s"
	fmtInnerIPHeaderDst := "udp[46:4] == %s"
	fmtFilter := "%s and ( %s and %s )"

	src, err := netip.ParseAddr(s.client.Address(features.IPFamilyV4))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse client pod IP: %w", err)
	}
	dst, err := netip.ParseAddr(s.server.Address(features.IPFamilyV4))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse server pod IP: %w", err)
	}

	srcBytes := src.As4()
	srcAsHex := fmt.Sprintf("0x%02x%02x%02x%02x", srcBytes[0], srcBytes[1], srcBytes[2], srcBytes[3])

	dstBytes := dst.As4()
	dstAsHex := fmt.Sprintf("0x%02x%02x%02x%02x", dstBytes[0], dstBytes[1], dstBytes[2], dstBytes[3])

	baseTunnelFilter, err := sniff.GetTunnelFilter(s.ct)
	if err != nil {
		return "", "", fmt.Errorf("failed to build tunnel filter: %w", err)
	}

	// InnerIP.Src(client) -> InnerIP.Dst(server)
	clientFilter = fmt.Sprintf(fmtFilter, baseTunnelFilter,
		fmt.Sprintf(fmtInnerIPHeaderSrc, srcAsHex),
		fmt.Sprintf(fmtInnerIPHeaderDst, dstAsHex))

	// InnerIP.Src(server) -> InnerIP.Dst(client)
	serverFilter = fmt.Sprintf(fmtFilter, baseTunnelFilter,
		fmt.Sprintf(fmtInnerIPHeaderSrc, dstAsHex),
		fmt.Sprintf(fmtInnerIPHeaderDst, srcAsHex))

	return clientFilter, serverFilter, nil
}

func (s *podToPodEncryptionV2) nativeTCPDumpFilters4(ctx context.Context) (clientFilter string, serverFilter string, err error) {
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("Context already cancelled")
	}

	// Native routing filter is much simpler, just check for the plain text
	// traffic.
	fmtNativeFilter := "src %s and dst %s"

	src, err := netip.ParseAddr(s.client.Address(features.IPFamilyV4))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse client pod IP: %w", err)
	}
	dst, err := netip.ParseAddr(s.server.Address(features.IPFamilyV4))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse server pod IP: %w", err)
	}

	clientFilter = fmt.Sprintf(fmtNativeFilter, src, dst)
	serverFilter = fmt.Sprintf(fmtNativeFilter, dst, src)
	return clientFilter, serverFilter, nil
}

// resolveTCPDumpFilters4 crafts a TCPDump filter which will be applied to
// s.clientEgressDev to detect any leaks.
//
// subtly, we cannot check for return traffic on each node.
//
// this is because in IPsec the return ESP traffic will arrive at
// s.clientEgressDev where we are TCPDumping.
//
// when XFRM decrypts this traffic it re-circulates the packet via the interface it
// arrived on original (s.clientEgressDev), at which point we will see the plain
// text packets arrive as they are decrypted and re-circulated by XFRM.
//
// to get around this we create filters for client-return-traffic that can be
// used server side, ensuring the return traffic is encrypted before leaving the
// host.
func (s *podToPodEncryptionV2) resolveTCPDumpFilters4(ctx context.Context) (clientFilter string, serverFilter string, err error) {
	// we have a context, may as well check it
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("Context already cancelled")
	}

	// handle tunneling mode.
	if s.tunnelMode.Enabled {
		return s.tunnelTCPDumpFilters4(ctx)
	}

	return s.nativeTCPDumpFilters4(ctx)
}

// icmpv6NAFilter filters ipv6 packets with icmpv6 type 136 (neighbor advertisement).
// These are sent unencrypted when node encryption and wireguard is enabled.
const icmpv6NAFilter = "not (icmp6 and ip6[40] = 136)"

// tunnelTCPDumpFilters6 is equivalent to tunnelTCPDumpFilters4 but for IPv6.
func (s *podToPodEncryptionV2) tunnelTCPDumpFilters6(ctx context.Context) (clientFilter string, serverFilter string, err error) {
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("Context already cancelled")
	}

	// Start at the UDP header (VXLAN|GENEVE) and index into IP6Header.Src and IP6Header.Dst
	// UDP(8)+VXLAN|GENEVE(8)+ETHER(14) = udp[30] + Offset to IP6Header.Src = udp[38]
	// UDP(8)+VXLAN|GENEVE(8)+ETHER(14) = udp[30] + Offset to IP6Header.Dst = udp[54]
	//
	// IP6 addresses are 16 bytes large, TCPDump syntax can peek at a maximum of
	// 4 bytes at a time, therefore we'll create 4 peek directives and slice up
	// the IPv6 address into groups of 4 byte words: (4peeks x 4bytes = 16byte IPv6 Address).
	innerIPv6Src := "(udp[38:4] == %s and udp[42:4] == %s and udp[46:4] == %s and udp[50:4] == %s)"
	innerIPv6Dst := "(udp[54:4] == %s and udp[58:4] == %s and udp[62:4] == %s and udp[66:4] == %s)"
	fmtFilter := "%s and %s and %s"

	src, err := netip.ParseAddr(s.client.Address(features.IPFamilyV6))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse client pod IP: %w", err)
	}
	dst, err := netip.ParseAddr(s.server.Address(features.IPFamilyV6))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse server pod IP: %w", err)
	}

	baseTunnelFilter, err := sniff.GetTunnelFilter(s.ct)
	if err != nil {
		return "", "", fmt.Errorf("failed to build tunnel filter: %w", err)
	}

	srcBytes := src.As16()
	srcWord1 := fmt.Sprintf("0x%02x%02x%02x%02x", srcBytes[0], srcBytes[1], srcBytes[2], srcBytes[3])
	srcWord2 := fmt.Sprintf("0x%02x%02x%02x%02x", srcBytes[4], srcBytes[5], srcBytes[6], srcBytes[7])
	srcWord3 := fmt.Sprintf("0x%02x%02x%02x%02x", srcBytes[8], srcBytes[9], srcBytes[10], srcBytes[11])
	srcWord4 := fmt.Sprintf("0x%02x%02x%02x%02x", srcBytes[12], srcBytes[13], srcBytes[14], srcBytes[15])

	dstBytes := dst.As16()
	dstWord1 := fmt.Sprintf("0x%02x%02x%02x%02x", dstBytes[0], dstBytes[1], dstBytes[2], dstBytes[3])
	dstWord2 := fmt.Sprintf("0x%02x%02x%02x%02x", dstBytes[4], dstBytes[5], dstBytes[6], dstBytes[7])
	dstWord3 := fmt.Sprintf("0x%02x%02x%02x%02x", dstBytes[8], dstBytes[9], dstBytes[10], dstBytes[11])
	dstWord4 := fmt.Sprintf("0x%02x%02x%02x%02x", dstBytes[12], dstBytes[13], dstBytes[14], dstBytes[15])

	clientInnerIPv6Src := fmt.Sprintf(innerIPv6Src, srcWord1, srcWord2, srcWord3, srcWord4)
	clientInnerIPv6Dst := fmt.Sprintf(innerIPv6Dst, dstWord1, dstWord2, dstWord3, dstWord4)

	serverInnerIPv6Src := fmt.Sprintf(innerIPv6Src, dstWord1, dstWord2, dstWord3, dstWord4)
	serverInnerIPv6Dst := fmt.Sprintf(innerIPv6Dst, srcWord1, srcWord2, srcWord3, srcWord4)

	clientFilter = fmt.Sprintf(fmtFilter, baseTunnelFilter, clientInnerIPv6Src, clientInnerIPv6Dst)
	serverFilter = fmt.Sprintf(fmtFilter, baseTunnelFilter, serverInnerIPv6Dst, serverInnerIPv6Src)

	return clientFilter, serverFilter, nil
}

func (s *podToPodEncryptionV2) nativeTCPDumpFilters6(ctx context.Context) (clientFilter string, serverFilter string, err error) {
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("Context already cancelled")
	}

	fmtNativeFilter := "src %s and dst %s"

	src, err := netip.ParseAddr(s.client.Address(features.IPFamilyV6))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse client pod IP: %w", err)
	}
	dst, err := netip.ParseAddr(s.server.Address(features.IPFamilyV6))
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse server pod IP: %w", err)
	}

	clientFilter = fmt.Sprintf(fmtNativeFilter, src, dst)
	serverFilter = fmt.Sprintf(fmtNativeFilter, dst, src)
	return clientFilter, serverFilter, nil
}

// resolveTCPDumpFilters6 is the analog of resolveTCPDumpFilters4 but for IPv6.
func (s *podToPodEncryptionV2) resolveTCPDumpFilters6(ctx context.Context) (clientFilter string, serverFilter string, err error) {
	if ctx.Err() != nil {
		return "", "", fmt.Errorf("Context already cancelled")
	}

	if s.tunnelMode.Enabled {
		clientFilter, serverFilter, err = s.tunnelTCPDumpFilters6(ctx)
	} else {
		clientFilter, serverFilter, err = s.nativeTCPDumpFilters6(ctx)
	}

	if err == nil {
		// If we have node encryption enabled with wireguard, filter out icmpv6 packets
		// that are neighbor broadcast messages as these are not sent to the WG device.
		encNode, ok := s.ct.Feature(features.EncryptionNode)
		if ok && encNode.Enabled && s.encryptMode.Mode == "wireguard" {
			clientFilter = fmt.Sprintf("(%s) and (%s)", clientFilter, icmpv6NAFilter)
			serverFilter = fmt.Sprintf("(%s) and (%s)", serverFilter, icmpv6NAFilter)
		}
	}

	return clientFilter, serverFilter, err
}

// startSniffers will start TCPdump on both the client and the server pod's host
// namespaces.
//
// if IPv6 is enabled for the cluster IPv6 specific sniffers will be started
// as well.
//
// if encryption is enabled we will put the sniffer into Assert mode where any
// captured packets indicates a test failure.
//
// conversely if encryption is disabled the sniffer is placed into Sanity mode
// where packets are expected. this is useful, in a rather indirect way,
// to prove that the generated tcpdump filters are working correctly and
// capturing the traffic traffic which would be a leak if encryption was enabled.
func (s *podToPodEncryptionV2) startSniffers(ctx context.Context, t *check.Test) error {
	if ctx.Err() != nil {
		return fmt.Errorf("Context already cancelled")
	}

	mode := sniff.ModeSanity
	if s.encryptMode.Enabled {
		t.Debugf("Encryption is enabled: test will fail if plain-text packets are seen.")
		mode = sniff.ModeAssert
	} else {
		t.Info("Encryption is disabled: test will fail if plain-text packets are not seen to validates pcap filters are correct")
	}

	var err error

	if s.ipv4Enabled.Enabled {
		s.clientSniffer4, err = sniff.Sniff(ctx, s.Name(), s.clientHostNS, s.clientEgressDev, s.clientFilter4, mode, t)
		if err != nil {
			return fmt.Errorf("Failed to start sniffer on client: %w", err)
		}
		t.Debugf("started client tcpdump sniffer: [client: %s] [node: %s] [dev: %s] [filter: %s] [mode: %s]",
			s.client.Pod.Name, s.client.Pod.Spec.NodeName, s.clientEgressDev, s.clientFilter4, mode)

		s.serverSniffer4, err = sniff.Sniff(ctx, s.Name(), s.serverHostNS, s.serverEgressDev, s.serverFilter4, mode, t)
		if err != nil {
			return fmt.Errorf("Failed to start sniffer on server: %w", err)
		}
		t.Debugf("started server tcpdump sniffer: [server: %s] [node: %s] [dev: %s] [filter: %s] [mode: %s]",
			s.server.Pod.Name, s.server.Pod.Spec.NodeName, s.serverEgressDev, s.serverFilter4, mode)
	}

	// if IPv6 is enabled on the cluster start IPv6 specific sniffers.
	// one may wonder why we have IPv6 specific tcpdump instances and do not create
	// a single filter which matches for both IPv4 and IPv6 traffic.
	//
	// the issue with this resides in the sanity check that is performed when
	// encryption is disabled.
	// this sanity check must ensure we see the traffic that **would be** a leak
	// if encryption was on, ensuring the filters are correct.
	//
	// a filter which matches for both IPv4 and IPv6 traffic may see one, or the
	// other, but not both, and confirm that the sanity check passed,
	// since **any** plain-text packets were observed.
	// this maybe a false positive tho, as you may have only seen IPv4 or IPv6,
	// and not both. therefore, maintain a sniffer-per-filter for the filters we
	// want to sanity check.
	if s.ipv6Enabled.Enabled {
		// subtly, this name is used to create the pcap file later evaluated
		// in sniff.Validate.
		//
		// we need to use a different name or else else both tcpdump instances
		// write to the same pcap file and this can break validation.
		name := fmt.Sprintf("%s-ipv6", s.Name())

		s.clientSniffer6, err = sniff.Sniff(ctx, name, s.clientHostNS, s.clientEgressDev, s.clientFilter6, mode, t)
		if err != nil {
			return fmt.Errorf("Failed to start sniffer on client for IPv6: %w", err)
		}
		t.Debugf("started client tcpdump sniffer for IPv6: [client: %s] [node: %s] [dev: %s] [filter: %s] [mode: %s]",
			s.client.Pod.Name, s.client.Pod.Spec.NodeName, s.clientEgressDev, s.clientFilter6, mode)

		s.serverSniffer6, err = sniff.Sniff(ctx, name, s.serverHostNS, s.serverEgressDev, s.serverFilter6, mode, t)
		if err != nil {
			return fmt.Errorf("Failed to start sniffer on server for IPv6: %w", err)
		}
		t.Debugf("started server tcpdump sniffer for IPv6: [server: %s] [node: %s] [dev: %s] [filter: %s] [mode: %s]",
			s.server.Pod.Name, s.server.Pod.Spec.NodeName, s.serverEgressDev, s.serverFilter6, mode)
	}

	return nil
}

// clientToServerTest creates and runs a check.Action which performs a curl
// from the client to the server pod.
//
// the action then checks the client sniffer initialized and ran in s.startSniffers
// to ensure packets are seen (when encryption is disabled) or leaked packets are
// not seen (when encryption is enabled).
func (s *podToPodEncryptionV2) clientToServerTest(ctx context.Context, t *check.Test) error {
	if ctx.Err() != nil {
		return fmt.Errorf("Context already cancelled")
	}

	if s.ipv4Enabled.Enabled {
		t.Debugf("performing client->server curl: [client: %s] [server: %s] [family: ipv4]", s.client.Pod.Name, s.server.Pod.Name)
		action := t.NewAction(s, fmt.Sprintf("curl-%s", features.IPFamilyV4), s.client, s.server, features.IPFamilyV4)
		action.Run(func(a *check.Action) {
			a.ExecInPod(ctx, a.CurlCommand(s.server))
			s.clientSniffer4.Validate(ctx, a)
			s.serverSniffer4.Validate(ctx, a)
		})
	}

	if s.ipv6Enabled.Enabled {
		t.Debugf("performing client->server curl: [client: %s] [server: %s] [family: ipv6]", s.client.Pod.Name, s.server.Pod.Name)
		action := t.NewAction(s, fmt.Sprintf("curl-%s", features.IPFamilyV6), s.client, s.server, features.IPFamilyV6)
		action.Run(func(a *check.Action) {
			a.ExecInPod(ctx, a.CurlCommand(s.server))
			s.clientSniffer6.Validate(ctx, a)
			s.serverSniffer6.Validate(ctx, a)
		})
	}

	return nil
}

func (s *podToPodEncryptionV2) Run(ctx context.Context, t *check.Test) {
	s.ct = t.Context()

	// grab the features influencing this test
	var ok bool
	s.ipv4Enabled, ok = s.ct.Feature(features.IPv4)
	if !ok {
		t.Fatalf("Failed to detect IPv4 feature")
	}
	s.ipv6Enabled, ok = s.ct.Feature(features.IPv6)
	if !ok {
		t.Fatalf("Failed to detect IPv6 feature")
	}
	s.tunnelMode, ok = s.ct.Feature(features.Tunnel)
	if !ok {
		t.Fatalf("Failed to detect tunnel mode")
	}
	s.encryptMode, ok = s.ct.Feature(features.EncryptionPod)
	if !ok {
		t.Fatalf("Failed to detect encryption mode")
	}

	if !s.ipv4Enabled.Enabled && !s.ipv6Enabled.Enabled {
		t.Fatalf("Test requires at least one IP family to be enabled")
	}

	// grab client and server pod, server must be on another host
	s.client = s.ct.RandomClientPod()
	if s.client == nil {
		t.Fatalf("Failed to acquire a client pod\n")
	}

	for _, pod := range s.ct.EchoPods() {
		if pod.Pod.Status.HostIP != s.client.Pod.Status.HostIP {
			s.server = &pod
			break
		}
	}
	if s.server == nil {
		t.Fatalf("Failed to acquire a server pod\n")
	}

	// grab host namespace pods for accessing the network namespaces of client
	// and server pods.
	if clientHostNS, ok := s.ct.HostNetNSPodsByNode()[s.client.Pod.Spec.NodeName]; !ok {
		t.Fatalf("Fail to acquire host namespace pod on %s\n (client's node)", s.client.Pod.Spec.NodeName)
	} else {
		s.clientHostNS = &clientHostNS
	}

	if serverHostNS, ok := s.ct.HostNetNSPodsByNode()[s.server.Pod.Spec.NodeName]; !ok {
		t.Fatalf("Fail to acquire host namespace pod on %s\n (server's node)", s.server.Pod.Spec.NodeName)
	} else {
		s.serverHostNS = &serverHostNS
	}

	// resolve the egress device on the client where traffic toward the server
	// will leave the host, and the egress device on the server where the return
	// traffic will leave the host.
	var err error
	s.clientEgressDev, err = s.resolveClientEgressDevice(ctx)
	if err != nil {
		t.Fatalf("Failed to resolve egress device for client: %v", err)
	}

	s.serverEgressDev, err = s.resolveServerEgressDevice(ctx)
	if err != nil {
		t.Fatalf("Failed to resolve egress device for server: %v", err)
	}

	// resolve the client and server's pcap filters used for leak detection,
	if s.ipv4Enabled.Enabled {
		s.clientFilter4, s.serverFilter4, err = s.resolveTCPDumpFilters4(ctx)
		if err != nil {
			t.Fatalf("Failed to resolve pcap filter: %v", err)
		}
	}
	if s.ipv6Enabled.Enabled {
		s.clientFilter6, s.serverFilter6, err = s.resolveTCPDumpFilters6(ctx)
		if err != nil {
			t.Fatalf("Failed to resolve pcap filter for IPv6: %v", err)
		}
	}

	// start the client and server side tcpdump sniffers with the filters
	// resolved by s.resolveTCPDumpFilter4.
	if err := s.startSniffers(ctx, t); err != nil {
		t.Fatalf("Failed to start sniffers: %s", err)
	}

	// performs a curl from the client to the server and validate the tcpdump
	// sniffers do not detect leaked traffic (or detect plain-text if encryption
	// is not enabled)
	s.clientToServerTest(ctx, t)
}
