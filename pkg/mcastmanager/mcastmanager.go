// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcastmanager

import (
	"net/netip"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/multicast"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "mcast-manager")
)

// MCastManager manages IPv6 address
type MCastManager struct {
	mutex lock.Mutex

	// iface is the interface that mcast addresses are applied to
	iface string

	// addresses keeps track of all ipv6 addresses by grouping them based on the
	// last 3 bytes of the address. The last 3 bytes of an IPv6 address determines
	// the solicited node multicast address: https://tools.ietf.org/html/rfc4291#section-2.7.1
	addresses map[int32]map[netip.Addr]struct{}

	// state tracks all the IPv6 multicast addresses created by MCastManager
	state map[netip.Addr]struct{}
}

// New creates a McastManager instance. Create a dummy manager when iface is empty
// string.
func New(iface string) *MCastManager {
	return &MCastManager{
		addresses: make(map[int32]map[netip.Addr]struct{}),
		state:     make(map[netip.Addr]struct{}),
		iface:     iface,
	}
}

// AddAddress is called when a new endpoint is added
func (mgr *MCastManager) AddAddress(ipv6 netip.Addr) {
	if mgr.iface == "" || !ipv6.IsValid() {
		return
	}

	key := multicast.Address(ipv6).Key()

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	if _, ok := mgr.addresses[key]; !ok {
		// First IP that has the solicited node maddr
		mgr.joinGroup(ipv6)
		mgr.addresses[key] = map[netip.Addr]struct{}{}
	}

	mgr.addresses[key][ipv6] = struct{}{}
}

// RemoveAddress is called when an endpoint is removed
func (mgr *MCastManager) RemoveAddress(ipv6 netip.Addr) {
	if mgr.iface == "" || !ipv6.IsValid() {
		return
	}

	key := multicast.Address(ipv6).Key()

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	if m, ok := mgr.addresses[key]; ok {
		delete(m, ipv6)
		if len(m) == 0 {
			// Last IP that has the solicited node maddr
			mgr.leaveGroup(ipv6)
			delete(mgr.addresses, key)
		}
	}
}

func (mgr *MCastManager) joinGroup(ipv6 netip.Addr) {
	maddr := multicast.Address(ipv6).SolicitedNodeMaddr()
	if err := multicast.JoinGroup(mgr.iface, maddr); err != nil {
		log.WithError(err).WithField("maddr", maddr).Warn("failed to join multicast group")
		return
	}

	log.WithFields(logrus.Fields{
		"device": mgr.iface,
		"mcast":  maddr,
	}).Info("Joined multicast group")

	mgr.state[maddr] = struct{}{}
}

func (mgr *MCastManager) leaveGroup(ipv6 netip.Addr) {
	maddr := multicast.Address(ipv6).SolicitedNodeMaddr()
	if err := multicast.LeaveGroup(mgr.iface, maddr); err != nil {
		log.WithError(err).WithField("maddr", maddr).Warn("failed to leave multicast group")
		return
	}

	log.WithFields(logrus.Fields{
		"device": mgr.iface,
		"mcast":  maddr,
	}).Info("Left multicast group")

	delete(mgr.state, maddr)
}
