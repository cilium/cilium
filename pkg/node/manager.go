// Copyright 2016-2017 Authors of Cilium
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

package node

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/maps/tunnel"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// RouteType represents the route type to be configured when adding the node
// routes
type RouteType int

const (
	// TunnelRoute is the route type to set up the BPF tunnel maps
	TunnelRoute RouteType = 1 << iota
	// DirectRoute is the route type to set up the L3 route using iproute
	DirectRoute
)

var (
	mutex lock.RWMutex
	nodes = map[Identity]*Node{}
)

// GetNode returns the node with the given identity, if exists, from the nodes
// map.
func GetNode(ni Identity) *Node {
	mutex.RLock()
	n := nodes[ni]
	mutex.RUnlock()
	return n
}

func deleteNodeCIDR(ip *net.IPNet) {
	if ip == nil {
		return
	}

	if err := tunnel.DeleteTunnelEndpoint(ip.IP); err != nil {
		log.WithError(err).WithField(logfields.IPAddr, ip).Error("bpf: Unable to delete in tunnel endpoint map")
	}
}

func updateNodeCIDR(ip *net.IPNet, host net.IP) {
	if ip == nil {
		return
	}

	if err := tunnel.SetTunnelEndpoint(ip.IP, host); err != nil {
		log.WithError(err).WithField(logfields.IPAddr, ip).Error("bpf: Unable to update in tunnel endpoint map")
	}
}

// UpdateNode updates the new node in the nodes' map with the given identity.
// When using DirectRoute RouteType the field ownAddr should contain the IPv6
// address of the interface that can reach the other nodes.
func UpdateNode(ni Identity, n *Node, routesTypes RouteType, ownAddr net.IP) {
	mutex.Lock()
	defer mutex.Unlock()

	oldNode, oldNodeExists := nodes[ni]
	if (routesTypes & TunnelRoute) != 0 {
		if oldNodeExists {
			deleteNodeCIDR(oldNode.IPv4AllocCIDR)
			deleteNodeCIDR(oldNode.IPv6AllocCIDR)
		}
		// FIXME if PodCIDR is empty retrieve the CIDR from the KVStore
		log.WithFields(log.Fields{
			logfields.IPAddr:   n.GetNodeIP(false),
			logfields.V4Prefix: n.IPv4AllocCIDR,
			logfields.V6Prefix: n.IPv6AllocCIDR,
		}).Debug("bpf: Setting tunnel endpoint")

		nodeIP := n.GetNodeIP(false)
		updateNodeCIDR(n.IPv4AllocCIDR, nodeIP)
		updateNodeCIDR(n.IPv6AllocCIDR, nodeIP)
	}
	if (routesTypes & DirectRoute) != 0 {
		updateIPRoute(oldNode, n, ownAddr)
	}

	nodes[ni] = n
}

// DeleteNode remove the node from the nodes' maps and / or the L3 routes to
// reach that node.
func DeleteNode(ni Identity, routesTypes RouteType) {
	var err1, err2 error
	mutex.Lock()
	if n, ok := nodes[ni]; ok {
		if (routesTypes & TunnelRoute) != 0 {
			log.WithFields(log.Fields{
				logfields.IPAddr:   n.GetNodeIP(false),
				logfields.V4Prefix: n.IPv4AllocCIDR,
				logfields.V6Prefix: n.IPv6AllocCIDR,
			}).Debug("bpf: Removing tunnel endpoint")

			if n.IPv4AllocCIDR != nil {
				err1 = tunnel.DeleteTunnelEndpoint(n.IPv4AllocCIDR.IP)
				if err1 == nil {
					n.IPv4AllocCIDR = nil
				}
			}

			if n.IPv6AllocCIDR != nil {
				err2 = tunnel.DeleteTunnelEndpoint(n.IPv6AllocCIDR.IP)
				if err2 == nil {
					n.IPv6AllocCIDR = nil
				}
			}
		}
		if (routesTypes & DirectRoute) != 0 {
			deleteIPRoute(n)
		}
	}

	// Keep node around
	if err1 == nil && err2 == nil {
		delete(nodes, ni)
	}

	mutex.Unlock()
}

// updateIPRoute updates the IP routing entry for the given node n via the
// network interface that as ownAddr.
func updateIPRoute(oldNode, n *Node, ownAddr net.IP) {
	nodeIPv6 := n.GetNodeIP(true)
	scopedLog := log.WithField(logfields.V6Prefix, n.IPv6AllocCIDR)
	scopedLog.WithField(logfields.IPAddr, nodeIPv6).Debug("iproute: Setting endpoint v6 route for prefix via IP")

	nl, err := firstLinkWithv6(ownAddr)
	if err != nil {
		scopedLog.WithError(err).WithField(logfields.IPAddr, ownAddr).Error("iproute: Unable to get v6 interface with IP")
		return
	}
	dev := nl.Attrs().Name
	if dev == "" {
		scopedLog.WithField(logfields.IPAddr, ownAddr).Error("iproute: Unable to get v6 interface for address: empty interface name")
		return
	}

	if oldNode != nil {
		oldNodeIPv6 := oldNode.GetNodeIP(true)
		if oldNode.IPv6AllocCIDR.String() != n.IPv6AllocCIDR.String() ||
			!oldNodeIPv6.Equal(nodeIPv6) ||
			oldNode.dev != n.dev {
			// If any of the routing components changed, then remove the old entries

			err = routeDel(oldNodeIPv6.String(), oldNode.IPv6AllocCIDR.String(), oldNode.dev)
			if err != nil {
				log.WithError(err).WithFields(log.Fields{
					logfields.IPAddr:   oldNodeIPv6,
					logfields.V6Prefix: oldNode.IPv6AllocCIDR,
					"device":           oldNode.dev,
				}).Warn("Cannot delete old route during update")
			}
		}
	} else {
		n.dev = dev
	}

	// Always re add
	err = routeAdd(nodeIPv6.String(), n.IPv6AllocCIDR.String(), dev)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			logfields.IPAddr:   nodeIPv6,
			logfields.V6Prefix: n.IPv6AllocCIDR,
			"device":           dev,
		}).Warn("Cannot re-add route")
		return
	}
}

// deleteIPRoute deletes the routing entries previously created for the given
// node.
func deleteIPRoute(node *Node) {
	oldNodeIPv6 := node.GetNodeIP(true)

	err := routeDel(oldNodeIPv6.String(), node.IPv6AllocCIDR.String(), node.dev)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			logfields.IPAddr:   oldNodeIPv6,
			logfields.V6Prefix: node.IPv6AllocCIDR,
			"device":           node.dev,
		}).Warn("Cannot delete route")
	}
}

// firstLinkWithv6 returns the first network interface that contains the given
// IPv6 address.
func firstLinkWithv6(ip net.IP) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		addrs, _ := netlink.AddrList(l, netlink.FAMILY_V6)
		for _, a := range addrs {
			if ip.Equal(a.IP) {
				return l, nil
			}
		}
	}

	return nil, fmt.Errorf("No address found")
}

func routeAdd(dstNode, podCIDR, dev string) error {
	prog := "ip"

	// for example: ip -6 r a fd00::b dev eth0
	// TODO: don't add direct route if a subnet of that IP is already present
	// in the routing table
	args := []string{"-6", "route", "add", dstNode, "dev", dev}
	out, err := exec.Command(prog, args...).CombinedOutput()
	// Ignore file exists in case the route already exists
	if err != nil && !bytes.Contains(out, []byte("File exists")) {
		return fmt.Errorf("unable to add routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}

	// now we can add the pods cidr route via the other's node IP
	// for example: ip -6 r a f00d::ac1f:32:0:0/96 via fd00::b
	args = []string{"-6", "route", "add", podCIDR, "via", dstNode}
	out, err = exec.Command(prog, args...).CombinedOutput()
	// Ignore file exists in case the route already exists
	if err != nil && !bytes.Contains(out, []byte("File exists")) {
		return fmt.Errorf("unable to add routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}
	return nil
}

func routeDel(dstNode, podCIDR, dev string) error {
	prog := "ip"

	args := []string{"-6", "route", "del", podCIDR, "via", dstNode}
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to clean up old routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}

	args = []string{"-6", "route", "del", dstNode, "dev", dev}
	out, err = exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to clean up old routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}
	return nil
}
