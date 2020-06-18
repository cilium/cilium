// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mcastmanager

import (
	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/multicast"
	"github.com/sirupsen/logrus"
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
	addresses map[int32]map[string]struct{}

	// state tracks all the IPv6 multicast addresses created by MCastManager
	state map[string]struct{}
}

// New creates a McastManager instance. Create a dummy manager when iface is empty
// string.
func New(iface string) *MCastManager {
	return &MCastManager{
		addresses: make(map[int32]map[string]struct{}),
		state:     make(map[string]struct{}),
		iface:     iface,
	}
}

// AddAddress is called when a new endpoint is added
func (mgr *MCastManager) AddAddress(ipv6 addressing.CiliumIPv6) {
	if mgr.iface == "" || !ipv6.IsSet() {
		return
	}

	key := multicast.Address(ipv6).Key()

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	if _, ok := mgr.addresses[key]; !ok {
		// First IP that has the solicited node maddr
		mgr.joinGroup(ipv6)
		mgr.addresses[key] = map[string]struct{}{}
	}

	mgr.addresses[key][ipv6.String()] = struct{}{}
}

// RemoveAddress is called when an endpoint is removed
func (mgr *MCastManager) RemoveAddress(ipv6 addressing.CiliumIPv6) {
	if mgr.iface == "" || !ipv6.IsSet() {
		return
	}

	key := multicast.Address(ipv6).Key()

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	if m, ok := mgr.addresses[key]; ok {
		delete(m, ipv6.String())
		if len(m) == 0 {
			// Last IP that has the solicited node maddr
			mgr.leaveGroup(ipv6)
			delete(mgr.addresses, key)
		}
	}
}

func (mgr *MCastManager) joinGroup(ipv6 addressing.CiliumIPv6) {
	maddr := multicast.Address(ipv6).SolicitedNodeMaddr()
	if err := multicast.JoinGroup(mgr.iface, maddr.String()); err != nil {
		log.WithError(err).WithField("maddr", maddr).Warn("failed to join multicast group")
		return
	}

	log.WithFields(logrus.Fields{
		"device": mgr.iface,
		"mcast":  maddr,
	}).Info("Joined multicast group")

	mgr.state[maddr.String()] = struct{}{}
}

func (mgr *MCastManager) leaveGroup(ipv6 addressing.CiliumIPv6) {
	maddr := multicast.Address(ipv6).SolicitedNodeMaddr()
	if err := multicast.LeaveGroup(mgr.iface, maddr.String()); err != nil {
		log.WithError(err).WithField("maddr", maddr).Warn("failed to leave multicast group")
		return
	}

	log.WithFields(logrus.Fields{
		"device": mgr.iface,
		"mcast":  maddr,
	}).Info("Left multicast group")

	delete(mgr.state, maddr.String())
}
