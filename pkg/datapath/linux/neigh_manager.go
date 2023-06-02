package linux

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type NeighManager interface {
	Update(context.Context, *nodeTypes.Node) error
	Validate(context.Context) error
	Reconcile(context.Context) error
}

// neighborNode represents the current desired state representation
// for a node that should be written to the neighbors table.
type neighborNode struct {
	neighReconciler

	refCount uint64
	identity Identity
	ip       net.IP
	nextHop  map[string]string
}

type neighReconciler interface {
	insertNeighbor4() error
	insertNeighbor6() error
}

// TODO: This shouldn't even really have any Linux/Netlink specific implementation?
type neighborManager struct {
	nodes map[Identity]neighborNode
}

func (n *neighborManager) Update(ctx context.Context, newNode *nodeTypes.Node) {
	n.nodes[newNode.Identity()] = neighborNode{
		identity: newNode.Identity(),
		ip:       newNode.GetNodeIP(true),
	}
}

func (n *neighborManager) Realize() error {

}

// TODO: Ensure this is:
// * Idempotent
func (n *neighborNode) insertNeighbor4(
	ctx context.Context,
	link netlink.Link, // todo: have this be static???
	refresh bool) error {

	newNodeIP := n.IP
	nextHopIPv4 := make(net.IP, len(newNodeIP))
	copy(nextHopIPv4, newNodeIP)

	scopedLog := log.WithFields(logrus.Fields{
		logfields.LogSubsys: "node-neigh-debug",
		logfields.Interface: link.Attrs().Name,
		logfields.IPAddr:    newNodeIP,
	})

	nextHopIPv4, err := getNextHopIP(nextHopIPv4, link)
	if err != nil {
		scopedLog.WithError(err).Info("Unable to determine next hop address")
		return err
	}
	nextHopStr := nextHopIPv4.String()
	scopedLog = scopedLog.WithField(logfields.NextHop, nextHopIPv4)

	n.neighLock.Lock()
	defer n.neighLock.Unlock()

	if n.nextHopByNode4 == nil {
		n.nextHop = make(map[string]string)
	}
	n.nextHop[newNode.identity] = nextHopByLink

	nextHopIsNew := false
	if existingNextHopStr, found := n.nextHopByNode4[link.Attrs().Name]; found {
		if existingNextHopStr != nextHopStr {
			n.refCount -= 1
			if n.refCount <= 0 {
				//if n.neighNextHopRefCount.Delete(existingNextHopStr) {
				neigh, found := n.neighByNextHop[existingNextHopStr]
				if found {
					// Note that we don't move the removal via netlink which might
					// block from the hot path (e.g. with defer), as this case can
					// happen very rarely.
					//
					// The neighbor's HW address is ignored on delete. Only the IP
					// address and device is checked.
					if err := netlink.NeighDel(neigh); err != nil {
						scopedLog.WithFields(logrus.Fields{
							logfields.NextHop:   neigh.IP,
							logfields.LinkIndex: neigh.LinkIndex,
						}).WithError(err).Info("Unable to remove next hop")
					}
					delete(n.nextHop, existingNextHopStr)
					delete(n.neighLastPingByNextHop, existingNextHopStr)
				}
			}
			// Given nextHop has changed and we removed the old one, we
			// now need to increment ref counter for the new one.
			//nextHopIsNew = n.neighNextHopRefCount.Add(nextHopStr)
			n.refCount -= 1
		}
	} else {
		// nextHop for the given node was previously not found, so let's
		// increment ref counter. This can happen upon regular NodeUpdate
		// event or by the periodic ARP refresher which got executed before
		// NodeUpdate().
		nextHopIsNew = n.neighNextHopRefCount.Add(nextHopStr)
	}

	n.neighNextHopByNode4[newNode.Identity()][link.Attrs().Name] = nextHopStr
	nh := NextHop{
		Name:  nextHopStr,
		IP:    nextHopIPv4,
		IsNew: nextHopIsNew,
	}
	n.insertNeighborCommon(scopedLog, ctx, nh, link, refresh)
}
