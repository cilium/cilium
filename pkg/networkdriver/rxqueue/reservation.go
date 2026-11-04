// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"fmt"
	"slices"

	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type queueReservations struct {
	mu     lock.Mutex
	queues map[uint32]*queueReservation
	// Binding generations remain unique across individual reservation lifetimes.
	sequence uint64
}

type queueReservation struct {
	shareID kube_types.UID
	binding *queueBinding // optional attachment state, including failed or revoked bindings
}

func (m *RXQueueManager) reservationsFor(ifName string) *queueReservations {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.reservations == nil {
		m.reservations = make(map[string]*queueReservations)
	}
	reservations := m.reservations[ifName]
	if reservations == nil {
		reservations = &queueReservations{queues: make(map[uint32]*queueReservation)}
		m.reservations[ifName] = reservations
	}
	return reservations
}

func (d *RXQueueDevice) reserve(allocation types.DeviceAllocation, candidates []uint32) (*RXQueueDevice, error) {
	if err := validateAllocation(allocation); err != nil {
		return nil, err
	}

	podIfName := allocation.Config.PodIfName
	if podIfName == "" {
		podIfName = types.DefaultRXQueuePodIfName
	}
	if err := types.ValidateInterfaceName(podIfName); err != nil {
		return nil, fmt.Errorf("%w: invalid pod interface name %q: %w", errInvalidAllocation, podIfName, err)
	}
	if d.Prepared && (d.ShareID != allocation.ShareID || d.PodIfName != podIfName) {
		return nil, fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}
	if d.reservations == nil {
		return nil, fmt.Errorf("%w: RX queue reservation state is unavailable", errInvalidAllocation)
	}

	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	if d.reservations.queues == nil {
		d.reservations.queues = make(map[uint32]*queueReservation)
	}

	for _, queueID := range candidates {
		if reservation := d.reservations.queues[queueID]; reservation != nil {
			if reservation.shareID == allocation.ShareID {
				return d.preparedForAllocation(allocation.ShareID, podIfName, queueID), nil
			}
			continue
		}

		queue, err := netlinkNetDevQueueGetByName(d.PhysicalIfName, queueID)
		if err != nil {
			return nil, err
		}
		if queue.Lease != nil {
			continue
		}
		// Clear any steering rules targeting this queue before allocating it.
		// Old rules may remain if cilium-agent stopped before completing cleanup.
		if err := syncRXFlows(d.PhysicalIfName, queueID, nil); err != nil {
			return nil, fmt.Errorf("failed to clear RX flow rules for %s/%d: %w", d.PhysicalIfName, queueID, err)
		}

		d.reservations.queues[queueID] = &queueReservation{shareID: allocation.ShareID}
		return d.preparedForAllocation(allocation.ShareID, podIfName, queueID), nil
	}

	return nil, fmt.Errorf("%w on %s", errNoAvailableRXQueue, d.PhysicalIfName)
}

func (d *RXQueueDevice) restoreReservation() error {
	if !d.Prepared {
		return nil
	}
	if d.ShareID == "" || d.PodIfName == "" || !slices.Contains(d.ReservedQueueIDs, d.PhysicalQueueID) {
		return fmt.Errorf("%w: stored RX queue reservation is incomplete", errInvalidAllocation)
	}
	if d.reservations == nil {
		return fmt.Errorf("%w: RX queue reservation state is unavailable", errInvalidAllocation)
	}

	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	if d.reservations.queues == nil {
		d.reservations.queues = make(map[uint32]*queueReservation)
	}
	if reservation := d.reservations.queues[d.PhysicalQueueID]; reservation != nil {
		if reservation.shareID != d.ShareID {
			return fmt.Errorf("%w: RX queue %s/%d is already reserved", errInvalidAllocation, d.PhysicalIfName, d.PhysicalQueueID)
		}
		return nil
	}
	d.reservations.queues[d.PhysicalQueueID] = &queueReservation{shareID: d.ShareID}
	return nil
}

// releaseReservation removes the rules that target the queue and returns it to
// the reserved pool. Both happen under the reservation lock, so no flow update
// can program the queue in between.
func (d *RXQueueDevice) releaseReservation() error {
	if d.reservations == nil {
		return nil
	}
	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	reservation := d.reservations.queues[d.PhysicalQueueID]
	if reservation == nil || reservation.shareID != d.ShareID {
		return nil
	}
	if binding := reservation.binding; binding != nil {
		binding.Generation = 0
		binding.retired[binding.AttachmentID] = struct{}{}
	}
	if err := syncRXFlows(d.PhysicalIfName, d.PhysicalQueueID, nil); err != nil {
		return fmt.Errorf("failed to remove RX flow rules for %s/%d: %w", d.PhysicalIfName, d.PhysicalQueueID, err)
	}
	delete(d.reservations.queues, d.PhysicalQueueID)
	return nil
}

func (d *RXQueueDevice) preparedForAllocation(shareID kube_types.UID, podIfName string, physicalQueueID uint32) *RXQueueDevice {
	prepared := d.clone()
	prepared.Prepared = true
	prepared.ShareID = shareID
	prepared.PodIfName = podIfName
	prepared.PhysicalQueueID = physicalQueueID
	prepared.VirtualQueueID = firstLeasedRXQueueID
	return prepared
}

func (d *RXQueueDevice) clone() *RXQueueDevice {
	return &RXQueueDevice{
		PhysicalIfName:   d.PhysicalIfName,
		HardwareAddress:  d.HardwareAddress,
		MTU:              d.MTU,
		TotalRXQueues:    d.TotalRXQueues,
		ReservedQueueIDs: slices.Clone(d.ReservedQueueIDs),
		Prepared:         d.Prepared,
		ShareID:          d.ShareID,
		PodIfName:        d.PodIfName,
		PhysicalQueueID:  d.PhysicalQueueID,
		VirtualQueueID:   d.VirtualQueueID,
		Binding:          d.Binding.clone(),
		reservations:     d.reservations,
	}
}
