// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

func upsertIPsecLog(err error, spec string, loc, rem *net.IPNet, spi uint8, nodeID uint16) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Reason:   spec,
		logfields.SPI:      spi,
		logfields.LocalIP:  loc,
		logfields.RemoteIP: rem,
		logfields.NodeID:   fmt.Sprintf("0x%x", nodeID),
	})
	if err != nil {
		scopedLog.WithError(err).Error("IPsec enable failed")
	} else {
		scopedLog.Debug("IPsec enable succeeded")
	}
}

func (n *linuxNodeHandler) enableSubnetIPsec(v4CIDR, v6CIDR []*net.IPNet) {
	n.replaceHostRules()

	for _, cidr := range v4CIDR {
		if !option.Config.EnableEndpointRoutes {
			n.replaceNodeIPSecInRoute(cidr)
		}
		n.replaceNodeIPSecOutRoute(cidr)
	}

	for _, cidr := range v6CIDR {
		n.replaceNodeIPSecInRoute(cidr)
		n.replaceNodeIPSecOutRoute(cidr)
	}
}

func (n *linuxNodeHandler) enableIPsec(oldNode, newNode *nodeTypes.Node, nodeID uint16) {
	if newNode.IsLocal() {
		n.replaceHostRules()
	}

	if oldNode != nil && oldNode.BootID != newNode.BootID {
		n.ipsecUpdateNeeded[newNode.Identity()] = true
	}
	_, updateExisting := n.ipsecUpdateNeeded[newNode.Identity()]
	statesUpdated := true

	// In endpoint routes mode we use the stack to route packets after
	// the packet is decrypted so set skb->mark to zero from XFRM stack
	// to avoid confusion in netfilters and conntrack that may be using
	// the mark fields. This uses XFRM_OUTPUT_MARK added in 4.14 kernels.
	zeroMark := option.Config.EnableEndpointRoutes

	if n.nodeConfig.EnableIPv4 && (newNode.IPv4AllocCIDR != nil || n.subnetEncryption()) {
		update := n.enableIPsecIPv4(newNode, nodeID, zeroMark, updateExisting)
		statesUpdated = statesUpdated && update
	}
	if n.nodeConfig.EnableIPv6 && (newNode.IPv6AllocCIDR != nil || n.subnetEncryption()) {
		update := n.enableIPsecIPv6(newNode, nodeID, zeroMark, updateExisting)
		statesUpdated = statesUpdated && update
	}

	if updateExisting && statesUpdated {
		delete(n.ipsecUpdateNeeded, newNode.Identity())
	}
}

func (n *linuxNodeHandler) enableIPsecIPv4(newNode *nodeTypes.Node, nodeID uint16, zeroMark, updateExisting bool) bool {
	statesUpdated := true
	var spi uint8

	wildcardIP := net.ParseIP(wildcardIPv4)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.IPv4Mask(0, 0, 0, 0)}

	err := ipsec.IPsecDefaultDropPolicy(false)
	upsertIPsecLog(err, "default-drop IPv4", wildcardCIDR, wildcardCIDR, spi, 0)

	if newNode.IsLocal() {
		if n.subnetEncryption() {
			// FIXME: Remove the following four lines in Cilium v1.16
			if localCIDR := n.nodeAddressing.IPv4().AllocationCIDR(); localCIDR != nil {
				// This removes a bogus route that Cilium installed prior to v1.15
				_ = route.Delete(n.createNodeIPSecInRoute(localCIDR.IPNet))
			}
		} else {
			localCIDR := n.nodeAddressing.IPv4().AllocationCIDR().IPNet
			n.replaceNodeIPSecInRoute(localCIDR)
		}
	} else {
		// A node update that doesn't contain a BootID will cause the creation
		// of non-matching XFRM IN and OUT states across the cluster as the
		// BootID is used to generate per-node key pairs. Non-matching XFRM
		// states will result in XfrmInStateProtoError, causing packet drops.
		// An empty BootID should thus be treated as an error, and Cilium
		// should not attempt to derive per-node keys from it.
		if newNode.BootID == "" {
			log.Debugf("Unable to enable IPsec for node %s with empty BootID", newNode.Name)
			return false
		}

		remoteCiliumInternalIP := newNode.GetCiliumInternalIP(false)
		if remoteCiliumInternalIP == nil {
			return false
		}
		remoteIP := remoteCiliumInternalIP

		localCiliumInternalIP := n.nodeAddressing.IPv4().Router()
		localIP := localCiliumInternalIP

		if n.subnetEncryption() {
			localNodeInternalIP, err := getV4LinkLocalIP()
			if err != nil {
				log.WithError(err).Error("Failed to get local IPv4 for IPsec configuration")
			}
			remoteNodeInternalIP := newNode.GetNodeIP(false)

			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP = localNodeInternalIP
				remoteIP = remoteNodeInternalIP
			}

			for _, cidr := range n.nodeConfig.IPv4PodSubnets {
				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, zeroMark, updateExisting)
				upsertIPsecLog(err, "out IPv4", wildcardCIDR, cidr, spi, nodeID)
				if err != nil {
					statesUpdated = false
				}

				/* Insert wildcard policy rules for traffic skipping back through host */
				if err = ipsec.IpSecReplacePolicyFwd(cidr, localIP); err != nil {
					log.WithError(err).Warning("egress unable to replace policy fwd:")
				}

				spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localCiliumInternalIP, remoteCiliumInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting)
				upsertIPsecLog(err, "in CiliumInternalIPv4", wildcardCIDR, cidr, spi, nodeID)
				if err != nil {
					statesUpdated = false
				}

				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localNodeInternalIP, remoteNodeInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting)
				upsertIPsecLog(err, "in NodeInternalIPv4", wildcardCIDR, cidr, spi, nodeID)
				if err != nil {
					statesUpdated = false
				}
			}
		} else {
			localCIDR := n.nodeAddressing.IPv4().AllocationCIDR().IPNet
			remoteCIDR := newNode.IPv4AllocCIDR.IPNet
			n.replaceNodeIPSecOutRoute(remoteCIDR)
			spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, false, updateExisting)
			upsertIPsecLog(err, "out IPv4", wildcardCIDR, remoteCIDR, spi, nodeID)
			if err != nil {
				statesUpdated = false
			}

			/* Insert wildcard policy rules for traffic skipping back through host */
			if err = ipsec.IpSecReplacePolicyFwd(wildcardCIDR, localIP); err != nil {
				log.WithError(err).Warning("egress unable to replace policy fwd:")
			}

			spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, false, updateExisting)
			upsertIPsecLog(err, "in IPv4", localCIDR, wildcardCIDR, spi, nodeID)
			if err != nil {
				statesUpdated = false
			}
		}
	}
	return statesUpdated
}

func (n *linuxNodeHandler) enableIPsecIPv6(newNode *nodeTypes.Node, nodeID uint16, zeroMark, updateExisting bool) bool {
	statesUpdated := true
	var spi uint8

	wildcardIP := net.ParseIP(wildcardIPv6)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.CIDRMask(0, 128)}

	err := ipsec.IPsecDefaultDropPolicy(true)
	upsertIPsecLog(err, "default-drop IPv6", wildcardCIDR, wildcardCIDR, spi, 0)

	if newNode.IsLocal() {
		if n.subnetEncryption() {
			// FIXME: Remove the following four lines in Cilium v1.16
			if localCIDR := n.nodeAddressing.IPv6().AllocationCIDR(); localCIDR != nil {
				// This removes a bogus route that Cilium installed prior to v1.15
				_ = route.Delete(n.createNodeIPSecInRoute(localCIDR.IPNet))
			}
		} else {
			localCIDR := n.nodeAddressing.IPv6().AllocationCIDR().IPNet
			n.replaceNodeIPSecInRoute(localCIDR)
		}
	} else {
		// A node update that doesn't contain a BootID will cause the creation
		// of non-matching XFRM IN and OUT states across the cluster as the
		// BootID is used to generate per-node key pairs. Non-matching XFRM
		// states will result in XfrmInStateProtoError, causing packet drops.
		// An empty BootID should thus be treated as an error, and Cilium
		// should not attempt to derive per-node keys from it.
		if newNode.BootID == "" {
			log.Debugf("Unable to enable IPsec for node %s with empty BootID", newNode.Name)
			return false
		}

		remoteCiliumInternalIP := newNode.GetCiliumInternalIP(true)
		if remoteCiliumInternalIP == nil {
			return false
		}
		remoteIP := remoteCiliumInternalIP

		localCiliumInternalIP := n.nodeAddressing.IPv6().Router()
		localIP := localCiliumInternalIP

		if n.subnetEncryption() {
			localNodeInternalIP, err := getV6LinkLocalIP()
			if err != nil {
				log.WithError(err).Error("Failed to get local IPv6 for IPsec configuration")
			}
			remoteNodeInternalIP := newNode.GetNodeIP(true)

			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP = localNodeInternalIP
				remoteIP = remoteNodeInternalIP
			}

			for _, cidr := range n.nodeConfig.IPv6PodSubnets {
				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, zeroMark, updateExisting)
				upsertIPsecLog(err, "out IPv6", wildcardCIDR, cidr, spi, nodeID)
				if err != nil {
					statesUpdated = false
				}

				spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localCiliumInternalIP, remoteCiliumInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting)
				upsertIPsecLog(err, "in CiliumInternalIPv6", wildcardCIDR, cidr, spi, nodeID)
				if err != nil {
					statesUpdated = false
				}

				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localNodeInternalIP, remoteNodeInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting)
				upsertIPsecLog(err, "in NodeInternalIPv6", wildcardCIDR, cidr, spi, nodeID)
				if err != nil {
					statesUpdated = false
				}
			}
		} else {
			localCIDR := n.nodeAddressing.IPv6().AllocationCIDR().IPNet
			remoteCIDR := newNode.IPv6AllocCIDR.IPNet
			n.replaceNodeIPSecOutRoute(remoteCIDR)
			spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, false, updateExisting)
			upsertIPsecLog(err, "out IPv6", wildcardCIDR, remoteCIDR, spi, nodeID)
			if err != nil {
				statesUpdated = false
			}

			spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, false, updateExisting)
			upsertIPsecLog(err, "in IPv6", localCIDR, wildcardCIDR, spi, nodeID)
			if err != nil {
				statesUpdated = false
			}
		}
	}
	return statesUpdated
}

func (n *linuxNodeHandler) subnetEncryption() bool {
	return len(n.nodeConfig.IPv4PodSubnets) > 0 || len(n.nodeConfig.IPv6PodSubnets) > 0
}

func (n *linuxNodeHandler) removeEncryptRules() error {
	rule := route.Rule{
		Priority: 1,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableIPSec,
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("Delete previous IPv4 decrypt rule failed: %w", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("Delete previousa IPv4 encrypt rule failed: %w", err)
		}
	}

	if err := route.DeleteRouteTable(linux_defaults.RouteTableIPSec, netlink.FAMILY_V4); err != nil {
		log.WithError(err).Warn("Deletion of IPSec routes failed")
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRuleIPv6(rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("Delete previous IPv6 decrypt rule failed: %w", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRuleIPv6(rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("Delete previous IPv6 encrypt rule failed: %w", err)
		}
	}
	return nil
}

func (n *linuxNodeHandler) createNodeIPSecInRoute(ip *net.IPNet) route.Route {
	var device string

	if option.Config.Tunnel == option.TunnelDisabled {
		device = option.Config.EncryptInterface[0]
	} else {
		device = option.Config.TunnelDevice()
	}
	return route.Route{
		Nexthop: nil,
		Device:  device,
		Prefix:  *ip,
		Table:   linux_defaults.RouteTableIPSec,
		Proto:   linux_defaults.RouteProtocolIPSec,
		Type:    route.RTN_LOCAL,
	}
}

func (n *linuxNodeHandler) createNodeIPSecOutRoute(ip *net.IPNet) route.Route {
	return route.Route{
		Nexthop: nil,
		Device:  n.datapathConfig.HostDevice,
		Prefix:  *ip,
		Table:   linux_defaults.RouteTableIPSec,
		MTU:     n.nodeConfig.MtuConfig.GetRoutePostEncryptMTU(),
	}
}

// replaceNodeIPSecOutRoute replace the out IPSec route in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecOutRoute(ip *net.IPNet) {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Upsert(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
	}
}

// The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) deleteNodeIPSecOutRoute(ip *net.IPNet) {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Delete(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route OUT from the host routing table")
	}
}

// replaceNodeIPSecoInRoute replace the in IPSec routes in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecInRoute(ip *net.IPNet) {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return
		}
	}

	if err := route.Upsert(n.createNodeIPSecInRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route IN the host routing table")
	}
}

func (n *linuxNodeHandler) deleteIPsec(oldNode *nodeTypes.Node) {
	scopedLog := log.WithField(logfields.NodeName, oldNode.Name)
	scopedLog.Debugf("Removing IPsec configuration for node")

	nodeID := n.getNodeIDForNode(oldNode)
	if nodeID == 0 {
		scopedLog.Warning("No node ID found for node.")
	} else {
		ipsec.DeleteIPsecEndpoint(nodeID)
	}

	if n.nodeConfig.EnableIPv4 && oldNode.IPv4AllocCIDR != nil {
		old4RouteNet := &net.IPNet{IP: oldNode.IPv4AllocCIDR.IP, Mask: oldNode.IPv4AllocCIDR.Mask}
		// This is only needed in IPAM modes where we install one route per
		// remote pod CIDR.
		if !n.subnetEncryption() {
			n.deleteNodeIPSecOutRoute(old4RouteNet)
		}
	}

	if n.nodeConfig.EnableIPv6 && oldNode.IPv6AllocCIDR != nil {
		old6RouteNet := &net.IPNet{IP: oldNode.IPv6AllocCIDR.IP, Mask: oldNode.IPv6AllocCIDR.Mask}
		// See IPv4 case above.
		if !n.subnetEncryption() {
			n.deleteNodeIPSecOutRoute(old6RouteNet)
		}
	}

	delete(n.ipsecUpdateNeeded, oldNode.Identity())
}
