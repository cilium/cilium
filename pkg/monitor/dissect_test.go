// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestDissectSummary(t *testing.T) {

	srcMAC := "01:23:45:67:89:ab"
	dstMAC := "02:33:45:67:89:ab"

	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	for _, c := range []struct {
		Name       string
		IsL3Device bool
	}{{"L3Device", true}, {"L2Device", false}} {
		t.Run(c.Name, func(t *testing.T) {
			// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="A")
			data := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 16, 32, 0, 125, 182, 0, 0}
			if c.IsL3Device {
				// Remove ethernet layer.
				data = data[14:]
			}
			summary := GetDissectSummary(data, &decodeOpts{IsL3Device: c.IsL3Device})

			if c.IsL3Device {
				require.Empty(t, summary.Ethernet)
			} else {
				require.NotEmpty(t, summary.Ethernet)
			}

			require.NotEmpty(t, summary.IPv4)
			require.NotEmpty(t, summary.TCP)

			if c.IsL3Device {
				require.Nil(t, summary.L2)
			} else {
				require.Equal(t, srcMAC, summary.L2.Src)
				require.Equal(t, dstMAC, summary.L2.Dst)
			}

			require.Equal(t, srcIP, summary.L3.Src)
			require.Equal(t, dstIP, summary.L3.Dst)

			require.Equal(t, sport, summary.L4.Src)
			require.Equal(t, dport, summary.L4.Dst)

		})
	}

	srcMacOuter := "01:02:03:04:05:06"
	dstMacOuter := "11:12:13:14:15:16"

	srcIPOuter := "1.1.1.1"
	dstIPOuter := "2.2.2.2"

	sportOuter := "8472"
	dportOuter := "9999"

	for _, c := range []struct {
		Name string
		Flag string
		Data []byte
	}{
		// Ether(src="01:02:03:04:05:06", dst="11:12:13:14:15:16")/IP(src="1.1.1.1",dst="2.2.2.2")/UDP(sport=8472,dport=9999)/VXLAN(vni=2)/Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="S")
		{"VXLAN", "SYN", []byte{17, 18, 19, 20, 21, 22, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 90, 0, 1, 0, 0, 64, 17, 116, 141, 1, 1, 1, 1, 2, 2, 2, 2, 33, 24, 39, 15, 0, 70, 9, 229, 12, 0, 0, 3, 0, 0, 2, 0, 2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}},
		// Ether(src="01:02:03:04:05:06", dst="11:12:13:14:15:16")/IP(src="1.1.1.1",dst="2.2.2.2")/UDP(sport=8472,dport=9999)/GENEVE(vni=2,proto=0x6558)/Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="A")
		{"Geneve", "ACK", []byte{17, 18, 19, 20, 21, 22, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 90, 0, 1, 0, 0, 64, 17, 116, 141, 1, 1, 1, 1, 2, 2, 2, 2, 33, 24, 39, 15, 0, 70, 176, 143, 0, 0, 101, 88, 0, 0, 2, 0, 2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 16, 32, 0, 125, 182, 0, 0}},
	} {
		t.Run(c.Name, func(t *testing.T) {
			summary := GetDissectSummary(c.Data, &decodeOpts{IsVXLAN: c.Name == "VXLAN", IsGeneve: c.Name == "Geneve"})

			require.NotEmpty(t, summary.Ethernet)
			require.NotEmpty(t, summary.IPv4)
			require.NotEmpty(t, summary.TCP)

			require.Equal(t, srcMAC, summary.L2.Src)
			require.Equal(t, dstMAC, summary.L2.Dst)

			require.Equal(t, srcIP, summary.L3.Src)
			require.Equal(t, dstIP, summary.L3.Dst)

			require.Equal(t, sport, summary.L4.Src)
			require.Equal(t, dport, summary.L4.Dst)

			require.NotNil(t, summary.Tunnel)
			require.NotEmpty(t, summary.Tunnel.Ethernet)
			require.NotEmpty(t, summary.Tunnel.IPv4)
			require.NotEmpty(t, summary.Tunnel.UDP)
			switch c.Name {
			case "VXLAN":
				require.NotEmpty(t, summary.Tunnel.VXLAN)
			case "GENEVE":
				require.NotEmpty(t, summary.Tunnel.GENEVE)
			}

			require.Equal(t, srcMacOuter, summary.Tunnel.L2.Src)
			require.Equal(t, dstMacOuter, summary.Tunnel.L2.Dst)

			require.Equal(t, srcIPOuter, summary.Tunnel.L3.Src)
			require.Equal(t, dstIPOuter, summary.Tunnel.L3.Dst)

			require.Equal(t, sportOuter, summary.Tunnel.L4.Src)
			require.Equal(t, dportOuter, summary.Tunnel.L4.Dst)
		})
	}
}

func TestDissect(t *testing.T) {
	for _, c := range []struct {
		Name string
		opts decodeOpts
		Data []byte
	}{
		// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443)
		{"Native", decodeOpts{}, []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}},
		// Ether(src="01:02:03:04:05:06", dst="11:12:13:14:15:16")/IP(src="1.1.1.1",dst="2.2.2.2")/UDP(sport=8472,dport=9999)/GENEVE(vni=2,proto=0x6558)/Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="A")
		{"Geneve", decodeOpts{IsGeneve: true}, []byte{17, 18, 19, 20, 21, 22, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 90, 0, 1, 0, 0, 64, 17, 116, 141, 1, 1, 1, 1, 2, 2, 2, 2, 33, 24, 39, 15, 0, 70, 176, 143, 0, 0, 101, 88, 0, 0, 2, 0, 2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 16, 32, 0, 125, 182, 0, 0}},
		// IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="A")
		{"NativeL3", decodeOpts{IsL3Device: true}, []byte{69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 16, 32, 0, 125, 182, 0, 0}},
	} {
		t.Run(c.Name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := bufio.NewWriter(&buf)

			// Ensure dissect=false prints raw data.
			Dissect(writer, false, c.Data, &c.opts)
			writer.Flush()
			require.Equal(t, hex.Dump(c.Data), buf.String())

			// Ensure dissect=true prints each decoded layer.
			buf = bytes.Buffer{}
			writer = bufio.NewWriter(&buf)
			Dissect(writer, true, c.Data, &c.opts)
			writer.Flush()
			lines := strings.Split(buf.String(), "\n")
			require.NotZero(t, lines)

			switch {
			case c.opts.IsGeneve:
				require.Len(t, lines, 8)
				require.True(t, strings.HasPrefix(lines[0], "Ethernet"))
				require.True(t, strings.HasPrefix(lines[1], "IPv4"))
				require.True(t, strings.HasPrefix(lines[2], "UDP"))
				require.True(t, strings.HasPrefix(lines[3], "Geneve"))
				require.True(t, strings.HasPrefix(lines[4], "Ethernet"))
				require.True(t, strings.HasPrefix(lines[5], "IPv4"))
				require.True(t, strings.HasPrefix(lines[6], "TCP"))
			case c.opts.IsL3Device:
				require.Len(t, lines, 3)
				require.True(t, strings.HasPrefix(lines[0], "IPv4"))
				require.True(t, strings.HasPrefix(lines[1], "TCP"))
			default:
				require.Len(t, lines, 4)
				require.True(t, strings.HasPrefix(lines[0], "Ethernet"))
				require.True(t, strings.HasPrefix(lines[1], "IPv4"))
				require.True(t, strings.HasPrefix(lines[2], "TCP"))
			}
		})
	}
}

func TestConnectionSummaryTcp(t *testing.T) {
	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	for _, c := range []struct {
		Name       string
		IsL3Device bool
	}{{"L3Device", true}, {"L2Device", false}} {
		t.Run(c.Name, func(t *testing.T) {
			// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="A")
			data := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 16, 32, 0, 125, 182, 0, 0}
			if c.IsL3Device {
				// Remove ethernet layer.
				data = data[14:]
			}
			summary := GetConnectionSummary(data, &decodeOpts{IsL3Device: c.IsL3Device})

			expect := fmt.Sprintf("%s -> %s %s",
				net.JoinHostPort(srcIP, sport),
				net.JoinHostPort(dstIP, dport),
				"tcp ACK")
			require.Equal(t, expect, summary)
		})
	}

	srcIPOuter := "1.1.1.1"
	dstIPOuter := "2.2.2.2"

	sportOuter := "8472"
	dportOuter := "9999"

	for _, c := range []struct {
		Name string
		Flag string
		Data []byte
	}{
		// Ether(src="01:02:03:04:05:06", dst="11:12:13:14:15:16")/IP(src="1.1.1.1",dst="2.2.2.2")/UDP(sport=8472,dport=9999)/VXLAN(vni=2)/Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="S")
		{"VXLAN", "SYN", []byte{17, 18, 19, 20, 21, 22, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 90, 0, 1, 0, 0, 64, 17, 116, 141, 1, 1, 1, 1, 2, 2, 2, 2, 33, 24, 39, 15, 0, 70, 9, 229, 12, 0, 0, 3, 0, 0, 2, 0, 2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}},
		// Ether(src="01:02:03:04:05:06", dst="11:12:13:14:15:16")/IP(src="1.1.1.1",dst="2.2.2.2")/UDP(sport=8472,dport=9999)/GENEVE(vni=2,proto=0x6558)/Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="A")
		{"Geneve", "ACK", []byte{17, 18, 19, 20, 21, 22, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 90, 0, 1, 0, 0, 64, 17, 116, 141, 1, 1, 1, 1, 2, 2, 2, 2, 33, 24, 39, 15, 0, 70, 176, 143, 0, 0, 101, 88, 0, 0, 2, 0, 2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 16, 32, 0, 125, 182, 0, 0}},
	} {
		t.Run(c.Name, func(t *testing.T) {
			summary := GetConnectionSummary(c.Data, &decodeOpts{IsVXLAN: c.Name == "VXLAN", IsGeneve: c.Name == "Geneve"})

			expect := fmt.Sprintf("%s -> %s %s [tunnel %s -> %s %s]",
				net.JoinHostPort(srcIP, sport),
				net.JoinHostPort(dstIP, dport),
				"tcp "+c.Flag,
				net.JoinHostPort(srcIPOuter, sportOuter),
				net.JoinHostPort(dstIPOuter, dportOuter),
				strings.ToLower(c.Name))

			require.Equal(t, expect, summary)
		})
	}

	t.Run("PostOverlay", func(t *testing.T) {
		// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443,flags="S")
		data := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}
		summary := GetConnectionSummary(data, nil)

		expect := fmt.Sprintf("%s -> %s %s",
			net.JoinHostPort(srcIP, sport),
			net.JoinHostPort(dstIP, dport),
			"tcp SYN")
		require.Equal(t, expect, summary)
	})
}

func TestConnectionSummaryIcmp(t *testing.T) {
	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/ICMP(type=3, code=1)
	packetData := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 28, 0, 1, 0, 0, 64, 1, 106, 205, 1, 2, 3, 4, 5, 6, 7, 8, 3, 1, 252, 254, 0, 0, 0, 0}

	summary := GetConnectionSummary(packetData, nil)

	expect := fmt.Sprintf("%s -> %s %s",
		srcIP,
		dstIP,
		"icmp DestinationUnreachable(Host)")
	require.Equal(t, expect, summary)
}

func TestConnectionSummaryVrrp(t *testing.T) {
	srcIP := net.ParseIP("1.2.3.4").To4()
	dstIP := net.ParseIP("224.0.0.18").To4()

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x12},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolVRRP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	vrrpPayload := []byte{
		0x21,       // Version 2, Type 1 (Advertisement)
		0x0a,       // VRID: 10
		0x78,       // Priority: 120
		0x01,       // Count IP Addrs: 1
		0x00,       // Auth Type: 0
		0x01,       // Advertisement Interval: 1
		0x00, 0x00, // Checksum (placeholder)

		// Virtual IP Address (192.168.1.1)
		0xc0, 0xa8, 0x01, 0x01,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayer, gopacket.Payload(vrrpPayload))
	require.NoError(t, err)

	packetData := buf.Bytes()
	summary := GetConnectionSummary(packetData, nil)

	expect := fmt.Sprintf("%s -> %s vrrp VRRPv2 Advertisement 10 120", srcIP, dstIP)
	require.Equal(t, expect, summary)
}

func TestConnectionSummaryIgmp(t *testing.T) {
	srcIP := net.ParseIP("1.2.3.4").To4()
	groupAddress := net.ParseIP("224.0.0.251").To4()

	// Construct the entire packet as a byte array directly
	packetData := []byte{
		// Ethernet Header (14 bytes)
		0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, // Dst MAC
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Src MAC
		0x08, 0x00, // EtherType: IPv4

		// IPv4 Header (20 bytes)
		0x45, 0x00, // Version, IHL, DSCP, ECN
		0x00, 0x1c, // Total Length: 28 (20 IP + 8 IGMP)
		0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
		0x01, 0x02, // TTL, Protocol (IGMP)
		0x00, 0x00, // Checksum (will be calculated)
		0x01, 0x02, 0x03, 0x04, // Src IP
		0xe0, 0x00, 0x00, 0xfb, // Dst IP

		// IGMP (8 bytes)
		0x16,       // Type: Membership Report v2
		0x00,       // Max Resp Code
		0xf9, 0x05, // Checksum
		0xe0, 0x00, 0x00, 0xfb, // Group Address
	}

	summary := GetConnectionSummary(packetData, nil)

	expect := fmt.Sprintf("%s -> %s igmp IGMPv2 Membership Report %s",
		srcIP.String(),
		groupAddress.String(),
		groupAddress.String())
	require.Equal(t, expect, summary)
}
