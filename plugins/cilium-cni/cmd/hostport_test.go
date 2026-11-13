// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/plugins/cilium-cni/types"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedSocketDiagFindPortInSeparateNetNS(t *testing.T) {
	testutils.PrivilegedTest(t)

	hostDiag, err := newSocketDiag()
	if err != nil {
		t.Fatalf("open host socket diagnostic socket: %v", err)
	}
	defer hostDiag.Close()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("create network namespace: %v", err)
	}
	defer ns.Close()

	var tcpListener net.Listener
	var udpConn net.PacketConn
	err = ns.Do(func() error {
		var err error
		tcpListener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen on TCP port: %w", err)
		}
		udpConn, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			tcpListener.Close()
			return fmt.Errorf("listen on UDP port: %w", err)
		}

		tcpPort := uint16(tcpListener.Addr().(*net.TCPAddr).Port)
		udpPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
		diag, err := newSocketDiag()
		if err != nil {
			return fmt.Errorf("open namespace socket diagnostic socket: %w", err)
		}
		defer diag.Close()

		for _, test := range []struct {
			protocol string
			port     uint16
		}{{"tcp", tcpPort}, {"udp", udpPort}} {
			found, err := diag.findPort(test.protocol, unix.AF_INET, test.port,
				netip.MustParseAddr("127.0.0.1"))
			if err != nil {
				return fmt.Errorf("find %s port %d in namespace: %w",
					test.protocol, test.port, err)
			}
			if !found {
				return fmt.Errorf("SOCK_DIAG did not find bound %s port %d",
					test.protocol, test.port)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	defer udpConn.Close()

	for _, test := range []struct {
		protocol string
		port     uint16
	}{{"tcp", uint16(tcpListener.Addr().(*net.TCPAddr).Port)},
		{"udp", uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)}} {
		found, err := hostDiag.findPort(test.protocol, unix.AF_INET, test.port,
			netip.MustParseAddr("127.0.0.1"))
		if err != nil {
			t.Fatalf("find %s port %d in host namespace: %v",
				test.protocol, test.port, err)
		}
		if found {
			t.Logf("host namespace also has %s port %d; cannot assert namespace isolation",
				test.protocol, test.port)
		}
	}
}

func TestSocketAddressesConflict(t *testing.T) {
	for _, tc := range []struct {
		socket, requested string
		v6only, want      bool
	}{
		{"0.0.0.0", "::1", false, false},
		{"::", "127.0.0.1", true, false},
		{"::", "127.0.0.1", false, true},
		{"127.0.0.1", "0.0.0.0", false, true},
		{"127.0.0.1", "127.0.0.2", false, false},
	} {
		if got := socketAddressesConflict(netip.MustParseAddr(tc.socket), netip.MustParseAddr(tc.requested), tc.v6only); got != tc.want {
			t.Errorf("socket %s requested %s v6only=%t: got %t, want %t", tc.socket, tc.requested, tc.v6only, got, tc.want)
		}
	}
}

func TestPrivilegedSocketDiagIPv6Only(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	err = ns.Do(func() error {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet6{}); err != nil {
			return err
		}
		if err := unix.Listen(fd, 1); err != nil {
			return err
		}
		addr, err := unix.Getsockname(fd)
		if err != nil {
			return err
		}
		diag, err := newSocketDiag()
		if err != nil {
			return err
		}
		defer diag.Close()
		for _, tc := range []struct {
			address string
			want    bool
		}{{"127.0.0.1", false}, {"::1", true}} {
			got, err := diag.findPort("tcp", unix.AF_INET6, uint16(addr.(*unix.SockaddrInet6).Port), netip.MustParseAddr(tc.address))
			if err != nil {
				return err
			}
			if got != tc.want {
				t.Errorf("IPv6-only listener requested %s: got %t, want %t", tc.address, got, tc.want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrivilegedProcNetHostPortCheckInSeparateNetNS(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("create network namespace: %v", err)
	}
	defer ns.Close()

	var tcpListener net.Listener
	var udpConn net.PacketConn
	err = ns.Do(func() error {
		var err error
		tcpListener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen on TCP port: %w", err)
		}
		udpConn, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			tcpListener.Close()
			return fmt.Errorf("listen on UDP port: %w", err)
		}

		mappings := []hostPortKey{
			{protocol: "tcp", port: uint16(tcpListener.Addr().(*net.TCPAddr).Port),
				address: netip.MustParseAddr("127.0.0.1")},
			{protocol: "udp", port: uint16(udpConn.LocalAddr().(*net.UDPAddr).Port),
				address: netip.MustParseAddr("127.0.0.1")},
		}
		for _, mapping := range mappings {
			err := validateHostPortsProc([]hostPortKey{mapping})
			if err == nil {
				return fmt.Errorf("proc checker did not find %s port %d",
					mapping.protocol, mapping.port)
			}
			if !strings.Contains(err.Error(), "already in use") {
				return fmt.Errorf("unexpected proc checker error: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	defer udpConn.Close()
}

func TestParseProcSocketAddressNativeEndian(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "2001:db8::1234"} {
		address := netip.MustParseAddr(ip)
		bytes := address.AsSlice()
		var words []string
		for i := 0; i < len(bytes); i += 4 {
			words = append(words, fmt.Sprintf("%08X", binary.NativeEndian.Uint32(bytes[i:i+4])))
		}
		got, port, err := parseProcSocketAddress(strings.Join(words, "") + ":1F90")
		if err != nil || got != address || port != 8080 {
			t.Fatalf("parse %s: got %s:%d, err=%v", ip, got, port, err)
		}
	}
}

func TestHostPortNodePortOverlap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		min, max uint16
		ports    []int
		conflict bool
	}{
		{"below range", 30000, 32767, []int{29999}, false},
		{"lower boundary", 30000, 32767, []int{30000}, true},
		{"upper boundary", 30000, 32767, []int{32767}, true},
		{"above range", 30000, 32767, []int{32768}, false},
		{"custom range", 10000, 11000, []int{10500}, true},
		{"custom range permits default ports", 10000, 11000, []int{30000}, false},
		{"later mapping", 10000, 11000, []int{8080, 10500}, true},
		{"single port range", 10000, 10000, []int{10000}, true},
		{"disabled or no HostPorts", 30000, 32767, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise the same JSON representation returned by the agent API.
			data, err := json.Marshal(map[string]any{"NodePortMin": tc.min, "NodePortMax": tc.max})
			require.NoError(t, err)
			var config map[string]any
			require.NoError(t, runtime.JSONConsumer().Consume(bytes.NewReader(data), &config))
			var mappings []types.PortMapping
			for _, port := range tc.ports {
				mappings = append(mappings, types.PortMapping{HostPort: port})
			}
			err = validateHostPortNodePortOverlap(mappings, config)
			if tc.conflict {
				require.ErrorContains(t, err, "overlaps with the configured NodePort range")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHostPortNodePortRangeCompatibility(t *testing.T) {
	mappings := []types.PortMapping{{HostPort: 30000}}
	require.NoError(t, validateHostPortNodePortOverlap(mappings, nil))
	for _, config := range []map[string]any{
		{"NodePortMin": json.Number("30000")},
		{"NodePortMin": "30000", "NodePortMax": "32767"},
		{"NodePortMin": json.Number("32767"), "NodePortMax": json.Number("30000")},
		{"NodePortMin": json.Number("0"), "NodePortMax": json.Number("65536")},
		{"NodePortMin": json.Number("30000.5"), "NodePortMax": json.Number("32767")},
		{"NodePortMin": json.Number("invalid"), "NodePortMax": json.Number("32767")},
		{"NodePortMin": json.Number("30000"), "NodePortMax": json.Number("999999999999999999999999")},
	} {
		require.ErrorContains(t, validateHostPortNodePortOverlap(mappings, config), "invalid NodePort range")
	}
}
