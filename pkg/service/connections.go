// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"errors"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/sockets"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

var opSupported = true

func (s *Service) destroyConnectionsToBackend(be *lb.Backend) {
	if !opSupported {
		return
	}
	var (
		family   uint8
		protocol uint8
	)
	ip := net.IP(be.L3n4Addr.AddrCluster.Addr().AsSlice())
	l4Addr := be.L3n4Addr.L4Addr

	switch be.L3n4Addr.Protocol {
	case lb.UDP:
		protocol = unix.IPPROTO_UDP
	default:
		return
	}
	log.Debugf("handling connections to deleted backend %v", be.L3n4Addr)
	if be.L3n4Addr.IsIPv6() {
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
			log.Errorf("Forcefully terminating sockets connected to deleted service backends " +
				"not supported by underlying kernel: see kube-proxy free guide for " +
				"the required kernel configurations")
		} else {
			log.Errorf("Error while forcefully terminating sockets connected to"+
				"deleted service backend: %v. If you see any traffic going to such"+
				"deleted backends, consider restarting application pods sending the traffic.", err)
		}
	}
}

// backendConnectionHandler is added for dependency injection in tests.
type backendConnectionHandler struct{}

func (h backendConnectionHandler) Destroy(filter sockets.SocketFilter) error {
	return sockets.Destroy(filter)
}
