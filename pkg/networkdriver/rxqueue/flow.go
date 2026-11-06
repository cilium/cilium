// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

var (
	netlinkNetDevRxFlowInsert = netlink.NetDevRxFlowInsert
	netlinkNetDevRxFlowDelete = netlink.NetDevRxFlowDelete
	netlinkNetDevRxFlowList   = netlink.NetDevRxFlowList
	netlinkNetDevRxFlowGet    = netlink.NetDevRxFlowGet

	netlinkNetDevRxFlowActionGet = netlink.NetDevRxFlowActionGet

	netlinkNetDevRxFlowTableGet = netlink.NetDevRxFlowTableGet
)

// SyncRXFlows makes flows the only flow steering rules that direct traffic to
// queueID, provided that reserved queue still belongs to shareID, and does
// nothing otherwise. Rules are programmed while holding the reservation lock,
// so an update for an allocation that has been freed cannot reach a queue that
// was reserved again in the meantime.
func (d *RXQueueDevice) SyncRXFlows(shareID kube_types.UID, queueID uint32, flows []types.RXQueueFlow) error {
	if d.reservations == nil {
		return fmt.Errorf("%w: RX queue reservation state is unavailable", errInvalidAllocation)
	}
	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	owner, reserved := d.reservations.owners[queueID]
	if !reserved || shareID == "" || owner != shareID {
		return nil
	}
	return syncRXFlows(d.PhysicalIfName, queueID, flows)
}

// syncRXFlows makes flows the only flow steering rules on ifName that direct
// traffic to queueID. The queue is reserved for one allocation, so any other
// rule that targets it is removed. Callers hold the reservation lock.
func syncRXFlows(ifName string, queueID uint32, flows []types.RXQueueFlow) error {
	desired := make(map[types.RXQueueFlow]struct{}, len(flows))
	for _, flow := range flows {
		flow.DestinationIP = flow.DestinationIP.Unmap()
		if _, err := rxFlowMatch(flow); err != nil {
			return err
		}
		desired[flow] = struct{}{}
	}
	present, err := removeRXFlows(ifName, queueID, desired)
	if err != nil {
		return err
	}

	var missing []types.RXQueueFlow
	for flow := range desired {
		if _, found := present[flow]; !found {
			missing = append(missing, flow)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	locations, err := newRXFlowLocations(ifName, len(missing))
	if err != nil {
		return err
	}

	var errs []error
	for i, flow := range missing {
		errs = append(errs, insertRXFlow(ifName, queueID, flow, locations[i]))
	}
	return errors.Join(errs...)
}

// newRXFlowLocations returns n locations for new rules on ifName. Drivers are
// not required to choose rule locations themselves. Those that do report it,
// and get RX_CLS_LOC_ANY; for the others, the lowest unused locations within
// the rule table are used.
func newRXFlowLocations(ifName string, n int) ([]uint32, error) {
	table, err := netlinkNetDevRxFlowTableGet(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to read the RX flow rule table of %s: %w", ifName, err)
	}
	locations := make([]uint32, 0, n)
	if table.SpecialLocations {
		for range n {
			locations = append(locations, netlink.RX_CLS_LOC_ANY)
		}
		return locations, nil
	}

	used, err := netlinkNetDevRxFlowList(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to list RX flow rules on %s: %w", ifName, err)
	}
	for location := uint32(0); len(locations) < n; location++ {
		if table.Size != 0 && location >= table.Size {
			return nil, fmt.Errorf("RX flow rule table of %s is full", ifName)
		}
		if !slices.Contains(used, location) {
			locations = append(locations, location)
		}
	}
	return locations, nil
}

// removeRXFlows deletes every rule on ifName that delivers traffic directly to
// queueID unless it is a desired flow, whatever the rule matches on, and
// returns the desired flows that remain.
func removeRXFlows(ifName string, queueID uint32, desired map[types.RXQueueFlow]struct{}) (map[types.RXQueueFlow]struct{}, error) {
	locations, err := netlinkNetDevRxFlowList(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to list RX flow rules on %s: %w", ifName, err)
	}

	present := make(map[types.RXQueueFlow]struct{})
	var errs []error
	for _, location := range locations {
		action, err := netlinkNetDevRxFlowActionGet(ifName, location)
		switch {
		case errors.Is(err, unix.ENOENT):
			continue
		case err != nil:
			errs = append(errs, fmt.Errorf("failed to read RX flow rule %s/%d: %w", ifName, location, err))
			continue
		case !deliversToQueue(action, queueID):
			continue
		}

		// Keep the rule only if it is exactly a desired flow. A rule that
		// NetDevRxFlow cannot represent was not installed by the driver.
		rule, err := netlinkNetDevRxFlowGet(ifName, location)
		switch {
		case errors.Is(err, unix.ENOENT):
			continue
		case err != nil && !errors.Is(err, netlink.ErrNotImplemented):
			errs = append(errs, fmt.Errorf("failed to read RX flow rule %s/%d: %w", ifName, location, err))
			continue
		case err == nil:
			if flow, ok := rxFlowFromMatch(rule.Match); ok {
				_, wanted := desired[flow]
				_, duplicate := present[flow]
				if wanted && !duplicate {
					present[flow] = struct{}{}
					continue
				}
			}
		}
		if err := netlinkNetDevRxFlowDelete(ifName, location); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("failed to delete RX flow rule %s/%d: %w", ifName, location, err))
		}
	}
	return present, errors.Join(errs...)
}

// deliversToQueue reports whether action delivers packets directly to queueID
// of the device itself.
func deliversToQueue(action *netlink.NetDevRxFlowAction, queueID uint32) bool {
	return !action.Drop && !action.WakeOnLAN && action.VF == 0 && !action.UsesRSSContext &&
		action.Queue == queueID
}

func insertRXFlow(ifName string, queueID uint32, flow types.RXQueueFlow, location uint32) error {
	match, err := rxFlowMatch(flow)
	if err != nil {
		return err
	}
	_, err = netlinkNetDevRxFlowInsert(ifName, netlink.NetDevRxFlow{
		Match:    match,
		Action:   netlink.NetDevRxFlowAction{Queue: queueID},
		Location: location,
	})
	if err != nil {
		return fmt.Errorf("failed to steer %s destination %s to RX queue %s/%d: %w",
			flow.Protocol, netip.AddrPortFrom(flow.DestinationIP, flow.DestinationPort),
			ifName, queueID, err)
	}
	return nil
}

// rxFlowMatch returns the exact destination match that steers flow.
func rxFlowMatch(flow types.RXQueueFlow) (netlink.NetDevRxFlowMatch, error) {
	ip := flow.DestinationIP
	if !ip.IsValid() || !ip.IsGlobalUnicast() {
		return nil, fmt.Errorf("%w: invalid RX flow destination IP %q", errInvalidAllocation, ip)
	}
	if flow.DestinationPort == 0 {
		return nil, fmt.Errorf("%w: RX flow destination port must be between 1 and 65535", errInvalidAllocation)
	}

	dstIP := net.IP(ip.AsSlice())
	dstIPMask := net.IP(net.CIDRMask(ip.BitLen(), ip.BitLen()))
	ip4 := netlink.TCPIP4Fields{DstIP: dstIP, DstIPMask: dstIPMask, DstPort: flow.DestinationPort, DstPortMask: ^uint16(0)}
	ip6 := netlink.TCPIP6Fields{DstIP: dstIP, DstIPMask: dstIPMask, DstPort: flow.DestinationPort, DstPortMask: ^uint16(0)}
	switch {
	case ip.Is4() && flow.Protocol == corev1.ProtocolTCP:
		return netlink.TCP4Flow{TCPIP4Fields: ip4}, nil
	case ip.Is4() && flow.Protocol == corev1.ProtocolUDP:
		return netlink.UDP4Flow{TCPIP4Fields: ip4}, nil
	case ip.Is6() && flow.Protocol == corev1.ProtocolTCP:
		return netlink.TCP6Flow{TCPIP6Fields: ip6}, nil
	case ip.Is6() && flow.Protocol == corev1.ProtocolUDP:
		return netlink.UDP6Flow{TCPIP6Fields: ip6}, nil
	default:
		return nil, fmt.Errorf("%w: RX flow protocol must be TCP or UDP, got %q", errInvalidAllocation, flow.Protocol)
	}
}

// rxFlowFromMatch returns the flow that match steers if it has exactly the
// shape that rxFlowMatch produces.
func rxFlowFromMatch(match netlink.NetDevRxFlowMatch) (types.RXQueueFlow, bool) {
	var flow types.RXQueueFlow
	var dstIP net.IP
	switch m := match.(type) {
	case netlink.TCP4Flow:
		flow.Protocol, dstIP, flow.DestinationPort = corev1.ProtocolTCP, m.DstIP, m.DstPort
	case netlink.UDP4Flow:
		flow.Protocol, dstIP, flow.DestinationPort = corev1.ProtocolUDP, m.DstIP, m.DstPort
	case netlink.TCP6Flow:
		flow.Protocol, dstIP, flow.DestinationPort = corev1.ProtocolTCP, m.DstIP, m.DstPort
	case netlink.UDP6Flow:
		flow.Protocol, dstIP, flow.DestinationPort = corev1.ProtocolUDP, m.DstIP, m.DstPort
	default:
		return flow, false
	}
	ip, ok := netip.AddrFromSlice(dstIP)
	if !ok {
		return flow, false
	}
	flow.DestinationIP = ip
	want, err := rxFlowMatch(flow)
	return flow, err == nil && reflect.DeepEqual(want, match)
}
