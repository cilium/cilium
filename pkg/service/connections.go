// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/defaults"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var opSupported = true

func (s *Service) TerminateUDPConnectionsToBackend(l3n4Addr *lb.L3n4Addr) {
	// With socket-lb, existing client applications can continue to connect to
	// deleted backends. Destroy any client sockets connected to the deleted backend.
	if !(option.Config.EnableSocketLB || option.Config.BPFSocketLBHostnsOnly) {
		return
	}
	if !opSupported {
		return
	}
	var (
		family   uint8
		protocol uint8
	)
	ip := net.IP(l3n4Addr.AddrCluster.Addr().AsSlice())
	l4Addr := l3n4Addr.L4Addr

	switch l3n4Addr.Protocol {
	case lb.UDP:
		protocol = unix.IPPROTO_UDP
	default:
		return
	}
	s.logger.Debug("handling udp connections to deleted backend", logfields.Deleted, l3n4Addr)
	if l3n4Addr.IsIPv6() {
		family = syscall.AF_INET6
	} else {
		family = syscall.AF_INET
	}
	// Filter pod connections load-balanced to the passed service backend.
	//
	// When pod traffic is load-balanced to service backends, the cilium datapath
	// records entries in the sock rev nat map that store the pod socket cookie
	// (unique identifier in the kernel) along with the destination backend ip/port.
	checkSockInRevNat := func(id netlink.SocketID) bool {
		cookie := uint64(id.Cookie[1])
		cookie = cookie<<32 + uint64(id.Cookie[0])

		return s.lbmap.ExistsSockRevNat(cookie, id.Destination, id.DestinationPort)
	}

	err := s.backendConnectionHandler.Destroy(sockets.SocketFilter{
		Family:    family,
		Protocol:  protocol,
		DestIp:    ip,
		DestPort:  l4Addr.Port,
		DestroyCB: checkSockInRevNat,
	})
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			opSupported = false
			s.logger.Error("Forcefully terminating sockets connected to deleted service backends " +
				"not supported by underlying kernel: see kube-proxy free guide for " +
				"the required kernel configurations")
			return
		} else {
			s.logger.Error(
				"error while forcefully terminating sockets connected to "+
					"deleted service backend. Consider restarting any application pods sending traffic "+
					"to the backend",
				logfields.Error, err,
				logfields.L3n4Addr, l3n4Addr,
			)
		}
	}

	// Iterate over all pod network namespaces, and terminate any stale connections.
	if option.Config.EnableSocketLBPodConnectionTermination && !option.Config.BPFSocketLBHostnsOnly {
		files, err := os.ReadDir(defaults.NetNsPath)
		if err != nil {
			s.logger.Error(
				"Error opening the netns dir while "+
					"terminating connections to deleted service backend",
				logfields.Error, err,
				logfields.L3n4Addr, l3n4Addr,
				logfields.NetNSDir, defaults.NetNsPath,
			)
			return
		}

		for _, file := range files {
			ns, err := netns.OpenPinned(filepath.Join(defaults.NetNsPath, file.Name()))
			if err != nil {
				s.logger.Debug(
					"Error opening netns",
					logfields.Error, err,
					logfields.NetNSName, file.Name(),
				)
				continue
			}
			err = ns.Do(func() error {
				return s.backendConnectionHandler.Destroy(sockets.SocketFilter{
					Family:    family,
					Protocol:  protocol,
					DestIp:    ip,
					DestPort:  l4Addr.Port,
					DestroyCB: checkSockInRevNat,
				})
			})
			ns.Close()
			if err != nil {
				s.logger.Error(
					"error while forcefully terminating sockets in netns connected to "+
						"deleted service backend. Consider restarting any application pods sending traffic "+
						"to the backend",
					logfields.Error, err,
					logfields.L3n4Addr, l3n4Addr,
					logfields.NetNSName, file.Name(),
				)
				continue
			}
		}
	}
}

// backendConnectionHandler is added for dependency injection in tests.
type backendConnectionHandler struct {
	logger *slog.Logger
}

func (h backendConnectionHandler) Destroy(filter sockets.SocketFilter) error {
	return sockets.Destroy(filter)
}
