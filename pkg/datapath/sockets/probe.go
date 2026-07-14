// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// newSocketInetProbe is a unexported function to construct a new
// probe. We manage the lifecycle via the cell such that we can
// memoize results.
func newSocketInetProbe() *SocketInetProbe {
	return &SocketInetProbe{probeSocketFns: defaultProbeSocketFns}
}

type SocketInetProbe struct {
	sync.Mutex
	tcpProbed   bool
	udpProbed   bool
	tcpProbeErr error
	udpProbeErr error

	probeSocketFns
}

type closer interface {
	Close() error
}

func parsePort(a string) (uint16, error) {
	ap, err := netip.ParseAddrPort(a)
	if err != nil {
		return 0, err
	}
	return ap.Port(), nil
}

// testProbeSocketFns abstracts the socket-creation and privileged netlink
// inet_diag operations used while probing so that tests can substitute fakes
// and exercise the probing logic without CAP_NET_ADMIN.
type probeSocketFns struct {
	createProbeTCPSocket func(ctx context.Context) (lis *net.TCPListener, conn net.Conn, port uint16, err error)
	createProbeUDPSocket func() (closer, uint16, error)
	iterate              func(proto uint8, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error
	destroySocket        func(logger *slog.Logger, sock netlink.Socket, proto netlink.Proto, stateFilter uint32) error
}

func createProbeTCPSocket(ctx context.Context) (lis *net.TCPListener, conn net.Conn, port uint16, err error) {
	lis, err = net.ListenTCP("tcp", &net.TCPAddr{
		IP: net.IP{127, 0, 0, 1},
	})
	if err != nil {
		return nil, nil, 0, err
	}

	port, err = parsePort(lis.Addr().String())
	if err != nil {
		lis.Close()
		return nil, nil, 0, err
	}

	dialer := net.Dialer{}
	// According to the kernel; we cannot terminate tcp listener
	// sockets in the LIST state.
	// Therefore, we dial our listener to create a connection that
	// we can use to probe on.
	conn, err = dialer.DialContext(ctx, "tcp", "localhost:"+strconv.Itoa(int(port)))
	if err != nil {
		lis.Close()
		return nil, nil, 0, err
	}

	port, err = parsePort(conn.LocalAddr().String())
	if err != nil {
		lis.Close()
		conn.Close()
		return nil, nil, 0, err
	}

	return lis, conn, port, nil
}

func createProbeUDPSocket() (closer, uint16, error) {
	lis, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.IP{127, 0, 0, 1},
	})
	if err != nil {
		return nil, 0, err
	}

	port, err := parsePort(lis.LocalAddr().String())
	if err != nil {
		lis.Close()
		return nil, 0, err
	}

	return lis, port, nil
}

var defaultProbeSocketFns = probeSocketFns{
	createProbeTCPSocket: createProbeTCPSocket,
	createProbeUDPSocket: createProbeUDPSocket,
	iterate:              Iterate,
	destroySocket:        DestroySocket,
}

type inetProbe struct {
	proto      int
	filterMask uint32
	port       uint16
}

// probeForSockDestroy probes supported socket termination protocols.
// To do this reliably and portably, this creates a socket for udp/tcp
// and attempts to both list and destroy sockets to probe for the full
// suite of inet diag features; ensuring that the sockets.Destroy will
// successfully find and terminate sockets.
// This is sufficient for both ip4 and ip6.
func (p *SocketInetProbe) probeForSockDestroy(ctx context.Context, logger *slog.Logger, udp bool) error {
	var probe inetProbe

	if udp {
		udpSock, port, err := p.createProbeUDPSocket()
		if err != nil {
			return err
		}
		defer udpSock.Close()

		probe = inetProbe{
			proto:      unix.IPPROTO_UDP,
			filterMask: StateFilterUDP,
			port:       port,
		}
	} else {
		lis, tcpConn, port, err := p.createProbeTCPSocket(ctx)
		if err != nil {
			return err
		}
		defer lis.Close()
		defer tcpConn.Close()

		probe = inetProbe{
			proto:      unix.IPPROTO_TCP,
			filterMask: StateFilterTCP,
			port:       port,
		}
	}

	// Bail out early if the caller cancelled before we start iterating.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("failed to complete probes: %w", err)
	}

	ok := false
	count := 0
	lo := net.IP{127, 0, 0, 1}
	if err := p.iterate(uint8(probe.proto), unix.AF_INET, probe.filterMask, func(s *netlink.Socket, err error) error {
		// Abort the dump promptly on cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// A per-message error yields a nil socket; surface it and stop.
		if err != nil {
			return err
		}
		count++
		if s.ID.SourcePort == probe.port && s.ID.Source.Equal(lo) {
			logger.Debug("found probe socket, attempting destroy",
				logfields.Port, probe.port,
				logfields.Protocol, probe.proto)
			destroyErr := p.destroySocket(logger, *s, netlink.Proto(probe.proto), 0xff)
			if errors.Is(destroyErr, unix.ENOTSUP) {
				// Note: Returning error stops iteration and passes err through to
				// return value of Iterate.
				return fmt.Errorf("%w: operation to destroy probe socket is unsupported. "+
					"This likely means that kernel CONFIG_INET_DIAG_DESTROY must be set in order for this functionality to work",
					probes.ErrNotSupported)
			}
			if destroyErr != nil {
				return destroyErr
			}
			ok = true
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed while iterating sockets: %w", err)
	}
	if !ok {
		// Unexpected: if we saw other sockets (which is very likely on host ns) then we should
		// have found our test sockets.
		// By not wrapping in the ErrNotSupported error, we indicate that this is an unexpected error
		// not a legitimate probing error.
		if count > 0 {
			return fmt.Errorf("failed to find listener socket for inet diag destroy probe")
		} else {
			proto := "tcp"
			requiredConfig := "CONFIG_INET_TCP_DIAG"
			if probe.proto == unix.IPPROTO_UDP {
				proto = "udp"
				requiredConfig = "CONFIG_INET_UDP_DIAG"
			}
			return fmt.Errorf("%w: no netlink messages testing INET_DIAG listing for %s. "+
				"This indicates that the kernel does not have the appropriate kernel config set (%s)",
				probes.ErrNotSupported, proto, requiredConfig)
		}
	}
	return nil
}

// resultIsCached reports whether a previous probe produced a definitive result
// implying we can just return memoized results.
func resultIsCached(isProbed bool, probeErr error) bool {
	return isProbed && (probeErr == nil || errors.Is(probeErr, probes.ErrNotSupported))
}

// InetDiagDestroyTCPEnabled probes for CONFIG_INET_DIAG_DESTROY functionality for
// TCP.
func (p *SocketInetProbe) InetDiagDestroyTCPEnabled(logger *slog.Logger) error {
	p.Lock()
	defer p.Unlock()
	if resultIsCached(p.tcpProbed, p.tcpProbeErr) {
		return p.tcpProbeErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.tcpProbeErr = p.probeForSockDestroy(ctx, logger, false)
	p.tcpProbed = true
	return p.tcpProbeErr
}

// InetDiagDestroyUDPEnabled probes for CONFIG_INET_DIAG_DESTROY functionality for
// UDP.
func (p *SocketInetProbe) InetDiagDestroyUDPEnabled(logger *slog.Logger) error {
	p.Lock()
	defer p.Unlock()
	if resultIsCached(p.udpProbed, p.udpProbeErr) {
		return p.udpProbeErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.udpProbeErr = p.probeForSockDestroy(ctx, logger, true)
	p.udpProbed = true
	return p.udpProbeErr
}
