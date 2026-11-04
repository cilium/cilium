// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
)

var (
	netlinkLinkList      = safenetlink.LinkList
	netlinkGenlFamilyGet = netlink.GenlFamilyGet
	netkitPeersUnleased  = probeNetkitPeersUnleased
	peerNamespacePath    = defaults.NetNsPath
	peerNamespaceOpen    = netns.GetFromPath
	newPeerQueueReader   = func(ns netns.NsHandle) (peerQueueReader, error) {
		return netlink.NewHandleAt(ns, unix.NETLINK_GENERIC)
	}
	netdevHasParent = func(link netlink.Link) (bool, error) {
		_, err := os.Stat(filepath.Join("/sys/class/net", link.Attrs().Name, "device"))
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return err == nil, err
	}
)

type leasedRXQueue struct {
	ifName  string
	queueID uint32
}

type leaseTarget struct {
	ifIndex uint32
	netNSID int32
}

// ResetLeasedRXQueueFlows withdraws steering before IPAM can reuse addresses.
// Kernel leases, rather than the current configuration, identify the queues to
// inspect. Leases without steering rules need no cleanup. Cilium owns leases into
// its primary netkit interfaces; unknown owners with rules fail startup instead
// of having their rules removed. No leases may be created concurrently with this
// startup sweep.
func ResetLeasedRXQueueFlows(ctx context.Context, ownsNetkit func(netlink.Link) (bool, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	family, err := netlinkGenlFamilyGet(nl.NETDEV_FAMILY_NAME)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil // Kernels without this family cannot have queue leases.
	}
	if err != nil {
		return fmt.Errorf("failed to inspect netdev queue-leasing support: %w", err)
	}
	if !slices.ContainsFunc(family.Ops, func(op netlink.GenlOp) bool { return op.ID == nl.NETDEV_CMD_QUEUE_CREATE }) {
		return nil
	}
	links, err := netlinkLinkList()
	if err != nil {
		return fmt.Errorf("failed to list interfaces for RX queue recovery: %w", err)
	}
	queues, err := discoverLeasedRXQueues(ctx, links, ownsNetkit)
	if err != nil {
		return err
	}
	// Validate the complete inventory before touching any rules.
	for _, queue := range queues {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := syncRXFlows(queue.ifName, queue.queueID, nil); err != nil {
			return fmt.Errorf("failed to reset leased RX queue %s/%d: %w", queue.ifName, queue.queueID, err)
		}
	}
	return nil
}

func discoverLeasedRXQueues(ctx context.Context, links []netlink.Link, ownsNetkit func(netlink.Link) (bool, error)) ([]leasedRXQueue, error) {
	primaries := make(map[leaseTarget]netlink.Link)
	for _, link := range links {
		if netkit, ok := link.(*netlink.Netkit); ok && netkitIsPrimary(netkit) {
			target := leaseTarget{uint32(link.Attrs().ParentIndex), int32(link.Attrs().NetNsID)}
			if _, duplicate := primaries[target]; duplicate {
				primaries[target] = nil
			} else {
				primaries[target] = link
			}
		}
	}
	// Cilium leases only to the peer of a primary netkit in this namespace.
	// Without a primary, no Cilium-created lease can still reach a Pod.
	if len(primaries) == 0 || netkitPeersUnleased(primaries) {
		return nil, nil
	}
	var queues []leasedRXQueue
	for _, link := range links {
		// Kernel queue providers have dev->dev.parent. Their rtnetlink kind
		// alone does not distinguish physical devices from virtual devices.
		hasParent, err := netdevHasParent(link)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect parent of interface %s: %w", link.Attrs().Name, err)
		}
		if !hasParent {
			continue
		}
		attrs := link.Attrs()
		if attrs.Flags&net.FlagUp == 0 {
			if err := inspectDownRXQueueDevice(attrs.Name, attrs.Index); err != nil {
				return nil, err
			}
			continue
		}
		if attrs.NumRxQueues <= 0 {
			return nil, fmt.Errorf("interface %s does not report its RX queue count", attrs.Name)
		}
		for id := uint32(0); id < uint32(attrs.NumRxQueues); id++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			queue, err := netlinkNetDevQueueGet(attrs.Index, id, netlink.NetDevQueueTypeRx)
			if errors.Is(err, unix.EINVAL) && id > 0 {
				break // IFLA_NUM_RX_QUEUES can exceed real_num_rx_queues.
			}
			if errors.Is(err, unix.ENOENT) {
				// queue-get hides administratively down devices. A concurrent
				// link-down must not silently hide a surviving lease.
				current, lookupErr := netlinkLinkByName(attrs.Name)
				if lookupErr == nil && current.Attrs().Flags&net.FlagUp == 0 {
					if err := inspectDownRXQueueDevice(attrs.Name, attrs.Index); err != nil {
						return nil, err
					}
					break
				}
			}
			if err != nil {
				return nil, fmt.Errorf("failed to inspect RX queue %s/%d: %w", attrs.Name, id, err)
			}
			if queue.Lease == nil {
				continue
			}
			hasFlows, err := rxQueueHasFlows(attrs.Name, id)
			if err != nil {
				return nil, fmt.Errorf("failed to inspect RX queue %s/%d steering: %w", attrs.Name, id, err)
			}
			if !hasFlows {
				// Endpoint deletion can remove the Cilium programs while its
				// netkit and lease survive. A clean queue needs no ownership proof.
				continue
			}
			target := leaseTarget{queue.Lease.IfIndex, -1}
			if queue.Lease.NetNSIDSet {
				target.netNSID = queue.Lease.NetNSID
			}
			primary := primaries[target]
			if primary == nil || (queue.Lease.NetNSIDSet && queue.Lease.NetNSID < 0) {
				return nil, fmt.Errorf("RX queue %s/%d has an unknown or ambiguous lease owner", attrs.Name, id)
			}
			owned, err := ownsNetkit(primary)
			if err != nil {
				return nil, fmt.Errorf("failed to verify RX queue %s/%d owner: %w", attrs.Name, id, err)
			}
			if !owned {
				return nil, fmt.Errorf("RX queue %s/%d is leased to non-Cilium interface %s", attrs.Name, id, primary.Attrs().Name)
			}
			queues = append(queues, leasedRXQueue{attrs.Name, id})
		}
	}
	return queues, nil
}

func rxQueueHasFlows(ifName string, queueID uint32) (bool, error) {
	locations, err := netlinkNetDevRxFlowList(ifName)
	if err != nil {
		return false, err
	}
	for _, location := range locations {
		action, err := netlinkNetDevRxFlowActionGet(ifName, location)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return false, err
		}
		// RSS rules can reach multiple queues; their actions alone cannot
		// establish that this queue receives no traffic.
		if action.UsesRSSContext || deliversToQueue(action, queueID) {
			return true, nil
		}
	}
	return false, nil
}

type peerQueueReader interface {
	NetDevQueueGet(int, uint32, netlink.NetDevQueueType) (*netlink.NetDevQueue, error)
	Close() error
}

// probeNetkitPeersUnleased proves that no peer has a real queue 1. Allocated
// queue slots alone do not establish a lease. Failure to inspect any peer is
// inconclusive and leaves the caller to inspect physical queues instead.
func probeNetkitPeersUnleased(primaries map[leaseTarget]netlink.Link) bool {
	pending := make(map[int32][]int)
	for target, primary := range primaries {
		if primary == nil || int32(target.ifIndex) <= 0 || target.netNSID < 0 {
			return false
		}
		pending[target.netNSID] = append(pending[target.netNSID], int(target.ifIndex))
	}
	entries, err := os.ReadDir(peerNamespacePath)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		ns, err := peerNamespaceOpen(filepath.Join(peerNamespacePath, entry.Name()))
		if err != nil {
			continue
		}
		id, idErr := hostGetNetNSIDByFD(int(ns))
		peers, wanted := pending[int32(id)]
		if idErr != nil || !wanted {
			ns.Close()
			continue
		}
		handle, err := newPeerQueueReader(ns)
		ns.Close()
		if err != nil {
			return false
		}
		unleased := true
		for _, peer := range peers {
			if _, err := handle.NetDevQueueGet(peer, 1, netlink.NetDevQueueTypeRx); !errors.Is(err, unix.EINVAL) {
				unleased = false
				break
			}
		}
		handle.Close()
		if !unleased {
			return false
		}
		delete(pending, int32(id))
		if len(pending) == 0 {
			return true
		}
	}
	return false
}

const ntupleFeature = "rx-ntuple-filter"

func inspectDownRXQueueDevice(ifName string, ifIndex int) error {
	// queue-get cannot reveal leases while the NIC is down. No rules means no
	// stale steering. An unsupported query alone cannot establish that: the driver
	// may reject queries while down even if it retains rules and leases.
	locations, err := netlinkNetDevRxFlowList(ifName)
	if errors.Is(err, unix.EOPNOTSUPP) {
		// Skip devices that offer neither configurable nor active ntuple filters.
		// An absent feature or a failed feature query remains inconclusive.
		features, featuresErr := netlinkNetDevFeaturesGet(ifIndex)
		if ntuple, found := features[ntupleFeature]; featuresErr == nil && found && !ntuple.Hardware && !ntuple.Active {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("failed to inspect rules on down interface %s: %w", ifName, err)
	}
	if len(locations) != 0 {
		return fmt.Errorf("interface %s is down and has RX flow rules; bring it up to inspect queue lease ownership before IPAM starts", ifName)
	}
	return nil
}
