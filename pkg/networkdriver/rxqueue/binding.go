// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	netlinkns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	ciliumnetns "github.com/cilium/cilium/pkg/netns"
)

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

// LeaseRXQueue leases the reserved physical queue to queue one of the Pod's
// primary netkit, next to the queue that carries the regular datapath. CNI
// creates that interface before the Pod sandbox starts, so the Network Driver
// leases the queue when the sandbox starts, before any container runs. Leasing
// a queue that is already leased to the same interface is a no-op.
func (d *RXQueueDevice) LeaseRXQueue(podNS *ciliumnetns.NetNS) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared || d.ShareID == "" || d.PodIfName == "" {
		return fmt.Errorf("%w: RX queue must be reserved before it can be leased", errInvalidAllocation)
	}

	handle, err := newQueueNetlinkHandle(podNS)
	if err != nil {
		return fmt.Errorf("failed to open netlink sockets in Pod network namespace: %w", err)
	}
	defer handle.Close()

	peer, err := handle.LinkByName(d.PodIfName)
	if err != nil {
		return fmt.Errorf("failed to find Pod interface %s: %w", d.PodIfName, err)
	}
	peerNetkit, ok := peer.(*netlink.Netkit)
	if !ok || netkitIsPrimary(peerNetkit) {
		return fmt.Errorf("%w: Pod interface %s is not a netkit peer", errInvalidAllocation, d.PodIfName)
	}
	if peer.Attrs().NumRxQueues < int(firstLeasedRXQueueID+1) {
		return fmt.Errorf("Pod interface %s does not have capacity for a leased RX queue", d.PodIfName)
	}

	podNSID, err := ensureNetNSID(hostGetNetNSIDByFD, hostSetNetNSIDByFD, podNS.FD())
	if err != nil {
		return fmt.Errorf("failed to resolve Pod network namespace ID from host: %w", err)
	}

	physical, err := netlinkLinkByName(d.PhysicalIfName)
	if err != nil {
		return fmt.Errorf("failed to find physical interface %s: %w", d.PhysicalIfName, err)
	}
	queue, err := netlinkNetDevQueueGet(physical.Attrs().Index, d.PhysicalQueueID, netlink.NetDevQueueTypeRx)
	if err != nil {
		return fmt.Errorf("failed to inspect reserved RX queue %s/%d: %w", d.PhysicalIfName, d.PhysicalQueueID, err)
	}

	if queue.Lease == nil {
		rootNS, err := currentNetNS()
		if err != nil {
			return fmt.Errorf("failed to open host network namespace: %w", err)
		}
		defer rootNS.Close()

		rootNSID, err := netNSID(handle, rootNS.FD())
		if err != nil {
			return fmt.Errorf("failed to resolve host network namespace ID from Pod: %w", err)
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
			return fmt.Errorf("failed to lease RX queue %s/%d to %s: %w", d.PhysicalIfName, d.PhysicalQueueID, d.PodIfName, err)
		}
		if virtualQueueID != firstLeasedRXQueueID {
			return fmt.Errorf("kernel created virtual RX queue %d on %s, expected %d", virtualQueueID, d.PodIfName, firstLeasedRXQueueID)
		}

		queue, err = netlinkNetDevQueueGet(physical.Attrs().Index, d.PhysicalQueueID, netlink.NetDevQueueTypeRx)
		if err != nil {
			return fmt.Errorf("failed to verify RX queue lease %s/%d: %w", d.PhysicalIfName, d.PhysicalQueueID, err)
		}
	}
	if !leaseMatches(queue.Lease, peer.Attrs().Index, int32(podNSID)) {
		return fmt.Errorf("%w: RX queue %s/%d is leased by another interface", errNoAvailableRXQueue, d.PhysicalIfName, d.PhysicalQueueID)
	}
	return nil
}
