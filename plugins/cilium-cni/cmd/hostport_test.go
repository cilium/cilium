// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

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
