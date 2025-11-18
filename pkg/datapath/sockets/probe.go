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
	"sync"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var probeOnce sync.Once

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

func createProbeTCPSocket(ctx context.Context) (closer, uint16, error) {
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP: net.IP{127, 0, 0, 1},
	})
	if err != nil {
		return lis, 0, err
	}

	port, err := parsePort(lis.Addr().String())
	if err != nil {
		lis.Close()
		return lis, 0, err
	}

	// According to the kernel; we cannot terminate tcp listener
	// sockets in the LIST state.
	// Therefore, we dial our listener to create a connection that
	// we can use to probe on.
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: int(port),
	})
	if err != nil {
		lis.Close()
		return lis, 0, err
	}

	port, err = parsePort(conn.LocalAddr().String())
	if err != nil {
		lis.Close()
		return nil, 0, err
	}

	return lis, uint16(port), nil
}

func createProbeUDPSocket() (closer, uint16, error) {
	lis, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.IP{127, 0, 0, 1},
	})
	if err != nil {
		return lis, 0, err
	}

	port, err := parsePort(lis.LocalAddr().String())

	return lis, uint16(port), err
}

type inetProbe struct {
	proto      int
	filterMask uint32
	port       uint16
}

// probeForSockDestroy probes supported socket termination protocols.
// To do this reliably and portably, this creates sockets for udp/tcp
// and attempts to both list and destroy sockets to probe for the full
// suite of inet diag features; ensuring that the sockets.Destroy will
// successfully find and terminate sockets.
// This is sufficient for both ip4 and ip6.
func probeForSockDestroy(ctx context.Context, logger *slog.Logger, tcp, udp bool) error {
	protoProbes := []inetProbe{}

	if udp {
		udpSock, port, err := createProbeUDPSocket()
		if err != nil {
			return err
		}
		defer udpSock.Close()

		protoProbes = append(protoProbes, inetProbe{
			proto:      unix.IPPROTO_UDP,
			filterMask: StateFilterUDP,
			port:       port,
		})
	}

	if tcp {
		tcpSock, port, err := createProbeTCPSocket(ctx)
		if err != nil {
			return err
		}
		defer tcpSock.Close()

		protoProbes = append(protoProbes, inetProbe{
			proto:      unix.IPPROTO_TCP,
			filterMask: StateFilterTCP,
			port:       port,
		})
	}

	var errs error
	for _, probe := range protoProbes {
		ok := false
		count := 0
		lo := net.IP{127, 0, 0, 1}
		if err := Iterate(uint8(probe.proto), unix.AF_INET, probe.filterMask, func(s *netlink.Socket, err error) error {
			logger.Debug("found probe socket, attempting destroy",
				logfields.Port, probe.port,
				logfields.Protocol, probe.proto)
			count++
			if s.ID.SourcePort == uint16(probe.port) && s.ID.Source.Equal(lo) {
				logger.Debug("found probe socket, attempting destroy",
					logfields.Port, probe.port,
					logfields.Protocol, probe.proto)
				destroyErr := DestroySocket(slog.Default(), *s, netlink.Proto(probe.proto), 0xff)
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
			errs = errors.Join(errs, fmt.Errorf("failed while iterating sockets: %w", err))
			continue
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

				errs = errors.Join(errs, fmt.Errorf("%w: no netlink messages testing INET_DIAG listing for %s. "+
					"This indicates that the kernel does not have the appropriate kernel config set (%s)",
					probes.ErrNotSupported, proto, requiredConfig))
			}
		}
	}
	return errs
}

// InetDiagDestroyEnabled sets up a local listener socket on localhost
// and attempts to terminate it to probe for functionality enabled by
// CONFIG_INET_DIAG_DESTROY.
func InetDiagDestroyEnabled(logger *slog.Logger, probeTCP, probeUDP bool) error {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	probeOnce.Do(func() {
		err = probeForSockDestroy(ctx, logger, probeTCP, probeUDP)
	})
	return err
}
