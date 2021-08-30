// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package egressmap

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-egress")

const (
	PolicyMapName = "cilium_egress_policy_v4"
	CtMapName     = "cilium_egress_ct_v4"

	MaxPolicyEntries = 1 << 14
	MaxCtEntries     = 1 << 18

	MaxGatewayNodes = 64
)

var (
	EgressPolicyMap *egressPolicyMap
	EgressCtMap     *egressCtMap
)

// InsertEgressGateway adds a new egress gateway to the egress policy identified
// by the (source IP, destination CIDR, egress IP) tuple.
// If the policy does not exist, it will create a new one.
func InsertEgressGateway(sourceIP net.IP, destCIDR net.IPNet, egressIP, gatewayIP net.IP) error {
	log.WithFields(logrus.Fields{
		logfields.SourceIP:        sourceIP,
		logfields.DestinationCIDR: destCIDR,
		logfields.EgressIP:        egressIP,
		logfields.GatewayIP:       gatewayIP,
	}).Info("Adding egress gateway")

	val, err := EgressPolicyMap.Lookup(sourceIP, destCIDR)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("cannot lookup egress policy map: %w", err)
	}

	if val.Size == MaxGatewayNodes {
		return fmt.Errorf("maximum number of gateway nodes (%d) already reached for the egress policy", MaxGatewayNodes)
	}

	if !val.EgressIP.IP().Equal(egressIP) && val.Size != 0 {
		return fmt.Errorf("an existing egress policy for the same source and destination IPs tuple already exists with a different egress IP")
	}

	gatewayIPs := []net.IP{}
	for i := uint32(0); i < val.Size; i++ {
		gw := val.GatewayIPs[i].IP()
		if gw.Equal(gatewayIP) {
			return fmt.Errorf("egress policy already exists")
		}
		gatewayIPs = append(gatewayIPs, gw)
	}
	gatewayIPs = append(gatewayIPs, gatewayIP)

	if err := EgressPolicyMap.Update(sourceIP, destCIDR, egressIP, gatewayIPs); err != nil {
		return fmt.Errorf("cannot update egress policy map: %w", err)
	}

	return nil
}

// RemoveEgressPolicy removes an egress policy identified by the (source IP,
// destination CIDR) tuple.
// In addition to removing the policy, this function removes also all CT entries
// from the egress CT map which match the egress policy.
func RemoveEgressPolicy(sourceIP net.IP, destCIDR net.IPNet) error {
	log.WithFields(logrus.Fields{
		logfields.SourceIP:        sourceIP,
		logfields.DestinationCIDR: destCIDR,
	}).Info("Removing egress policy")

	val, err := EgressPolicyMap.Lookup(sourceIP, destCIDR)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("egress policy does not exist")
		}

		return fmt.Errorf("cannot lookup egress policy: %w", err)
	}

	gatewayIPs := []net.IP{}
	for i := uint32(0); i < val.Size; i++ {
		gatewayIPs = append(gatewayIPs, val.GatewayIPs[i].IP())
	}

	if err := EgressPolicyMap.Delete(sourceIP, destCIDR); err != nil {
		return err
	}

	// Remove from the CT table all the connections that were directed to
	// the egress gateway(s) we just deleted.
	// Entries are deleted _after_ the policy is deleted otherwise we may
	// end up creating entries which never get deleted.
	for _, gatewayIP := range gatewayIPs {
		if err = removeCtEntries(sourceIP, destCIDR, gatewayIP); err != nil {
			return err
		}
	}

	return nil
}

// RemoveEgressGateway removes a gateway IP from an egress policy identified by
// the (source IP, destination CIDR) tuple.
// In addition to removing the gateway IP, this function removes also all CT
// entries from the egress CT map which match the egress policy for the given
// gateway IP.
func RemoveEgressGateway(sourceIP net.IP, destCIDR net.IPNet, gatewayIP net.IP) error {
	log.WithFields(logrus.Fields{
		logfields.SourceIP:        sourceIP,
		logfields.DestinationCIDR: destCIDR,
		logfields.GatewayIP:       gatewayIP,
	}).Info("Removing egress gateway")

	val, err := EgressPolicyMap.Lookup(sourceIP, destCIDR)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("egress policy does not exist")
		}

		return fmt.Errorf("cannot lookup egress policy: %w", err)
	}

	// Remove gateway IP from the list of gateway IPs in the policy
	gatewayIPs := []net.IP{}
	for i := uint32(0); i < val.Size; i++ {
		gw := val.GatewayIPs[i].IP()
		if gw.Equal(gatewayIP) {
			continue
		}
		gatewayIPs = append(gatewayIPs, gw)
	}

	if val.Size == uint32(len(gatewayIPs)) {
		// We couldn't find the gateway in the list of gateways, return
		// an error
		return fmt.Errorf("cannot find gateway IP in egress policy")
	}

	if len(gatewayIPs) != 0 {
		// If there are still other gateway IPs associated with the
		// policy, update it
		if err := EgressPolicyMap.Update(sourceIP, destCIDR, val.EgressIP.IP(), gatewayIPs); err != nil {
			return err
		}
	} else {
		// Otherwise just delete the policy
		if err := EgressPolicyMap.Delete(sourceIP, destCIDR); err != nil {
			return err
		}
	}

	// Remove from the CT table all the connections that were directed to
	// the egress gateway we just deleted.
	// Entries are deleted _after_ the policy is updated/deleted otherwise
	// we may end up creating entries which never get deleted.
	return removeCtEntries(sourceIP, destCIDR, gatewayIP)
}

// InitEgressMaps initializes the egress policy and CT maps.
func InitEgressMaps() error {
	err := initEgressPolicyMap(PolicyMapName, true)
	if err != nil {
		return err
	}

	return initEgressCtMap(CtMapName, true)
}

// OpenEgressMaps initializes the egress policy and CT maps.
func OpenEgressMaps() error {
	err := initEgressPolicyMap(PolicyMapName, false)
	if err != nil {
		return err
	}

	return initEgressCtMap(CtMapName, false)
}
