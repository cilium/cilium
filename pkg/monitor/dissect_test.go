// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDissectSummary(t *testing.T) {

	srcMAC := "01:23:45:67:89:ab"
	dstMAC := "02:33:45:67:89:ab"

	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443)
	packetData := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}

	summary := GetDissectSummary(packetData)

	require.NotEmpty(t, summary.Ethernet)
	require.NotEmpty(t, summary.IPv4)
	require.NotEmpty(t, summary.TCP)

	require.Equal(t, srcMAC, summary.L2.Src)
	require.Equal(t, dstMAC, summary.L2.Dst)

	require.Equal(t, srcIP, summary.L3.Src)
	require.Equal(t, dstIP, summary.L3.Dst)

	require.Equal(t, sport, summary.L4.Src)
	require.Equal(t, dport, summary.L4.Dst)
}

func TestConnectionSummaryTcp(t *testing.T) {
	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443)
	l2Data := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0}
	l3Data := []byte{69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}

	for _, c := range []struct {
		Name       string
		IsL3Device bool
	}{{"L3Device", true}, {"L2Device", false}} {
		t.Run(c.Name, func(t *testing.T) {
			var data []byte
			if c.IsL3Device {
				data = l3Data
			} else {
				data = slices.Concat(l2Data, l3Data)
			}
			summary := GetConnectionSummary(data, &decodeOpts{IsL3Device: c.IsL3Device})

			expect := fmt.Sprintf("%s -> %s %s",
				net.JoinHostPort(srcIP, sport),
				net.JoinHostPort(dstIP, dport),
				"tcp SYN")
			require.Equal(t, expect, summary)
		})
	}

	srcIPOuter := "1.1.1.1"
	dstIPOuter := "2.2.2.2"

	sportOuter := "8472"
	dportOuter := "9999"

	for _, c := range []struct {
		Name string
		Data []byte
	}{
		// Ether(src="01:02:03:04:05:06", dst="11:12:13:14:15:16")/IP(src="1.1.1.1",dst="2.2.2.2")/UDP(sport=8472,dport=9999)/VXLAN(vni=2)
		{"VXLAN", []byte{17, 18, 19, 20, 21, 22, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 36, 0, 1, 0, 0, 64, 17, 116, 195, 1, 1, 1, 1, 2, 2, 2, 2, 33, 24, 39, 15, 0, 16, 167, 161, 8, 0, 0, 0, 0, 0, 2, 0}},
		// Ether(src="01:02:03:04:05:06", dst="11:12:13:14:15:16")/IP(src="1.1.1.1",dst="2.2.2.2")/UDP(sport=8472,dport=9999)/GENEVE(vni=2,proto=0x6558)
		{"Geneve", []byte{17, 18, 19, 20, 21, 22, 1, 2, 3, 4, 5, 6, 8, 0, 69, 0, 0, 36, 0, 1, 0, 0, 64, 17, 116, 195, 1, 1, 1, 1, 2, 2, 2, 2, 33, 24, 39, 15, 0, 16, 74, 73, 0, 0, 101, 88, 0, 0, 2, 0}},
	} {
		t.Run(c.Name, func(t *testing.T) {
			data := slices.Concat(c.Data, l2Data, l3Data)
			summary := GetConnectionSummary(data, &decodeOpts{IsVXLAN: c.Name == "VXLAN", IsGeneve: c.Name == "Geneve"})

			expect := fmt.Sprintf("%s -> %s %s [tunnel %s -> %s %s]",
				net.JoinHostPort(srcIP, sport),
				net.JoinHostPort(dstIP, dport),
				"tcp SYN",
				net.JoinHostPort(srcIPOuter, sportOuter),
				net.JoinHostPort(dstIPOuter, dportOuter),
				strings.ToLower(c.Name))
			require.Equal(t, expect, summary)
		})
	}
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
