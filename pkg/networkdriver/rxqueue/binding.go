// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	netlinkns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	ciliumnetns "github.com/cilium/cilium/pkg/netns"
)

// RXQueueBinding identifies the CNI attachment allowed to steer traffic to a
// prepared queue. It is runtime state, not part of the serialized allocation.
type RXQueueBinding struct {
	AttachmentID string
	Generation   uint64
	Addresses    []netip.Addr
}

type queueBinding struct {
	RXQueueBinding
	peerIndex int
	peerNSID  int32
	retired   map[string]struct{}
}

func (b *RXQueueBinding) clone() *RXQueueBinding {
	if b == nil {
		return nil
	}
	clone := *b
	clone.Addresses = slices.Clone(b.Addresses)
	return &clone
}

type queueNetlinkHandle interface {
	LinkByName(string) (netlink.Link, error)
	NetDevQueueCreate(netlink.NetDevQueueCreateRequest) (uint32, error)
	GetNetNsIdByFd(int) (int, error)
	SetNetNsIdByFd(int, int) error
	Close() error
}

var (
	newQueueNetlinkHandle = func(ns *ciliumnetns.NetNS) (queueNetlinkHandle, error) {
		return netlink.NewHandleAt(netlinkns.NsHandle(ns.FD()), unix.NETLINK_ROUTE, unix.NETLINK_GENERIC)
	}
	currentNetNS       = ciliumnetns.Current
	netkitIsPrimary    = func(n *netlink.Netkit) bool { return n.IsPrimary() }
	hostGetNetNSIDByFD = netlink.GetNetNsIdByFd
	hostSetNetNSIDByFD = netlink.SetNetNsIdByFd
)

func netNSID(handle queueNetlinkHandle, fd int) (int, error) {
	return ensureNetNSID(handle.GetNetNsIdByFd, handle.SetNetNsIdByFd, fd)
}

func ensureNetNSID(
	get func(int) (int, error),
	set func(int, int) error,
	fd int,
) (int, error) {
	id, err := get(fd)
	if err != nil {
		return 0, err
	}
	if id >= 0 {
		return id, nil
	}
	if err := set(fd, -1); err != nil && !errors.Is(err, unix.EEXIST) {
		return 0, err
	}
	id, err = get(fd)
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, errors.New("kernel did not assign a network namespace ID")
	}
	return id, nil
}

func leaseMatches(lease *netlink.NetDevQueueLease, peerIfIndex int, peerNetNSID int32) bool {
	return lease != nil &&
		lease.IfIndex == uint32(peerIfIndex) &&
		lease.Queue.Type == netlink.NetDevQueueTypeRx &&
		lease.Queue.ID == firstLeasedRXQueueID &&
		lease.NetNSIDSet &&
		lease.NetNSID == peerNetNSID
}

// BindRXQueue leases queue one of the Pod's primary netkit and authorizes flows
// only for this CNI attachment's addresses. Replacing an attachment invalidates
// delayed flow updates and clears its rules before exposing the new lease.
// A matching lease restored after agent restart can be adopted without churn.
func (d *RXQueueDevice) BindRXQueue(podNS *ciliumnetns.NetNS, attachmentID string, addresses []netip.Addr) (*RXQueueDevice, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared || d.ShareID == "" || d.PodIfName == "" || d.reservations == nil {
		return nil, fmt.Errorf("%w: RX queue must be reserved before it can be leased", errInvalidAllocation)
	}
	if attachmentID == "" || len(addresses) == 0 {
		return nil, fmt.Errorf("%w: CNI attachment and addresses are required", errInvalidAllocation)
	}
	for _, address := range addresses {
		if !address.IsValid() || address.IsUnspecified() || address.Zone() != "" {
			return nil, fmt.Errorf("%w: invalid CNI attachment address %s", errInvalidAllocation, address)
		}
	}

	handle, err := newQueueNetlinkHandle(podNS)
	if err != nil {
		return nil, fmt.Errorf("failed to open netlink sockets in Pod network namespace: %w", err)
	}
	defer handle.Close()

	peer, err := handle.LinkByName(d.PodIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find Pod interface %s: %w", d.PodIfName, err)
	}
	peerNetkit, ok := peer.(*netlink.Netkit)
	if !ok || netkitIsPrimary(peerNetkit) {
		return nil, fmt.Errorf("%w: Pod interface %s is not a netkit peer", errInvalidAllocation, d.PodIfName)
	}
	if peer.Attrs().NumRxQueues < int(firstLeasedRXQueueID+1) {
		return nil, fmt.Errorf("Pod interface %s does not have capacity for a leased RX queue", d.PodIfName)
	}

	podNSID, err := ensureNetNSID(hostGetNetNSIDByFD, hostSetNetNSIDByFD, podNS.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Pod network namespace ID from host: %w", err)
	}

	physical, err := netlinkLinkByName(d.PhysicalIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interface %s: %w", d.PhysicalIfName, err)
	}

	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	reservation := d.reservations.queues[d.PhysicalQueueID]
	if reservation == nil || reservation.shareID != d.ShareID {
		return nil, fmt.Errorf("%w: RX queue reservation changed", errInvalidAllocation)
	}
	queue, err := netlinkNetDevQueueGet(physical.Attrs().Index, d.PhysicalQueueID, netlink.NetDevQueueTypeRx)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect reserved RX queue %s/%d: %w", d.PhysicalIfName, d.PhysicalQueueID, err)
	}
	// Reject a stale Run before invalidating the current attachment's binding.
	if queue.Lease != nil && !leaseMatches(queue.Lease, peer.Attrs().Index, int32(podNSID)) {
		return nil, fmt.Errorf("%w: RX queue %s/%d is leased by another interface", errNoAvailableRXQueue, d.PhysicalIfName, d.PhysicalQueueID)
	}
	binding := reservation.binding
	if binding != nil {
		if _, retired := binding.retired[attachmentID]; retired {
			return nil, fmt.Errorf("%w: CNI attachment %s was retired", errInvalidAllocation, attachmentID)
		}
		if binding.Generation != 0 && binding.AttachmentID == attachmentID {
			if queue.Lease == nil || binding.peerIndex != peer.Attrs().Index || binding.peerNSID != int32(podNSID) || !slices.Equal(binding.Addresses, addresses) {
				return nil, fmt.Errorf("%w: CNI attachment %s changed", errInvalidAllocation, attachmentID)
			}
			return d.boundSnapshot(binding), nil
		}
	} else {
		binding = &queueBinding{retired: make(map[string]struct{})}
		reservation.binding = binding
	}

	// A recovered matching kernel lease has no runtime binding yet. Otherwise
	// remove old rules before creating or adopting a replacement lease.
	adopt := binding.AttachmentID == "" && queue.Lease != nil
	if binding.AttachmentID != "" {
		binding.retired[binding.AttachmentID] = struct{}{}
	}
	binding.RXQueueBinding = RXQueueBinding{AttachmentID: attachmentID}
	failed := func(err error) (*RXQueueDevice, error) {
		binding.retired[attachmentID] = struct{}{}
		return d.boundSnapshot(binding), err
	}
	if !adopt {
		if err := syncRXFlows(d.PhysicalIfName, d.PhysicalQueueID, nil); err != nil {
			return failed(fmt.Errorf("failed to clear RX flow rules before binding %s: %w", attachmentID, err))
		}
	}

	if queue.Lease == nil {
		rootNS, err := currentNetNS()
		if err != nil {
			return failed(fmt.Errorf("failed to open host network namespace: %w", err))
		}
		defer rootNS.Close()

		rootNSID, err := netNSID(handle, rootNS.FD())
		if err != nil {
			return failed(fmt.Errorf("failed to resolve host network namespace ID from Pod: %w", err))
		}
		virtualQueueID, err := handle.NetDevQueueCreate(netlink.NetDevQueueCreateRequest{
			IfIndex: peer.Attrs().Index,
			Type:    netlink.NetDevQueueTypeRx,
			Lease: netlink.NetDevQueueLease{
				IfIndex: uint32(physical.Attrs().Index),
				Queue: netlink.NetDevQueueID{
					ID:   d.PhysicalQueueID,
					Type: netlink.NetDevQueueTypeRx,
				},
				NetNSID:    int32(rootNSID),
				NetNSIDSet: true,
			},
		})
		if err != nil {
			return failed(fmt.Errorf("failed to lease RX queue %s/%d to %s: %w", d.PhysicalIfName, d.PhysicalQueueID, d.PodIfName, err))
		}
		if virtualQueueID != firstLeasedRXQueueID {
			return failed(fmt.Errorf("kernel created virtual RX queue %d on %s, expected %d", virtualQueueID, d.PodIfName, firstLeasedRXQueueID))
		}

		queue, err = netlinkNetDevQueueGet(physical.Attrs().Index, d.PhysicalQueueID, netlink.NetDevQueueTypeRx)
		if err != nil {
			return failed(fmt.Errorf("failed to verify RX queue lease %s/%d: %w", d.PhysicalIfName, d.PhysicalQueueID, err))
		}
	}
	if !leaseMatches(queue.Lease, peer.Attrs().Index, int32(podNSID)) {
		return failed(fmt.Errorf("%w: RX queue %s/%d is leased by another interface", errNoAvailableRXQueue, d.PhysicalIfName, d.PhysicalQueueID))
	}
	d.reservations.sequence++
	binding.RXQueueBinding = RXQueueBinding{AttachmentID: attachmentID, Generation: d.reservations.sequence, Addresses: slices.Clone(addresses)}
	binding.peerIndex, binding.peerNSID = peer.Attrs().Index, int32(podNSID)
	return d.boundSnapshot(binding), nil
}

// RevokeRXQueueForIP withdraws the attachment before IPAM can reuse one of its
// addresses. Failed withdrawals retain their addresses so any later release,
// including the other address family, retries the same cleanup.
func (d *RXQueueDevice) RevokeRXQueueForIP(address netip.Addr) (*RXQueueDevice, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reservations == nil {
		return nil, nil
	}
	d.reservations.mu.Lock()
	defer d.reservations.mu.Unlock()
	reservation := d.reservations.queues[d.PhysicalQueueID]
	if reservation == nil || reservation.shareID != d.ShareID || reservation.binding == nil ||
		!slices.Contains(reservation.binding.Addresses, address.Unmap()) {
		return nil, nil
	}
	binding := reservation.binding
	binding.Generation = 0
	binding.retired[binding.AttachmentID] = struct{}{}
	// TODO: kernel/driver failure can leave DMA active even after queue teardown
	// reports success. Rule withdrawal is not a fail-closed DMA revocation barrier.
	err := syncRXFlows(d.PhysicalIfName, d.PhysicalQueueID, nil)
	if err == nil {
		binding.Addresses = nil
	}
	return d.boundSnapshot(binding), err
}

func (d *RXQueueDevice) boundSnapshot(binding *queueBinding) *RXQueueDevice {
	clone := d.clone()
	clone.Binding = nil
	if binding.Generation != 0 {
		clone.Binding = binding.RXQueueBinding.clone()
	}
	return clone
}
