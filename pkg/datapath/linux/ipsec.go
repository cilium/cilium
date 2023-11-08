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
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

func upsertIPsecLog(err error, spec string, loc, rem *net.IPNet, spi uint8, nodeID uint16) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Reason:   spec,
		logfields.SPI:      spi,
		logfields.LocalIP:  loc,
		logfields.RemoteIP: rem,
		logfields.NodeID:   fmt.Sprintf("0x%x", nodeID),
	})
	if err != nil {
		scopedLog.WithError(err).Error("IPsec enable failed")
		return fmt.Errorf("failed to enable ipsec with %s using local IP %s, rem %s, spi %d: %w",
			spec,
			loc.String(),
			rem.String(),
			spi, err)
	} else {
		scopedLog.Debug("IPsec enable succeeded")
	}
	return nil
}

func (n *linuxNodeHandler) registerIpsecMetricOnce() {
	n.ipsecMetricOnce.Do(func() {
		if err := metrics.Register(n.ipsecMetricCollector); err != nil {
			log.WithError(err).Error("IPSec metrics registration failed. No metrics will be reported!")
		}
	})
}

func (n *linuxNodeHandler) enableSubnetIPsec(v4CIDR, v6CIDR []*net.IPNet) error {
	errs := n.replaceHostRules()
	for _, cidr := range v4CIDR {
		if !option.Config.EnableEndpointRoutes {
			if err := n.replaceNodeIPSecInRoute(cidr); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec IN (%q): %w", cidr.IP, err))
			}
		}
		if err := n.replaceNodeIPSecOutRoute(cidr); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec OUT (%q): %w", cidr.IP, err))
		}
	}

	for _, cidr := range v6CIDR {
		if err := n.replaceNodeIPSecInRoute(cidr); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec IN (%q): %w", cidr.IP, err))
		}

		if err := n.replaceNodeIPSecOutRoute(cidr); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec OUT (%q): %w", cidr.IP, err))
		}
	}
	return errs
}

func (n *linuxNodeHandler) enableIPsec(newNode *nodeTypes.Node, nodeID uint16) error {
	var errs error
	if newNode.IsLocal() {
		if err := n.replaceHostRules(); err != nil {
			errs = fmt.Errorf("failed to replace host rules: %w", err)
		}
	}

	// In endpoint routes mode we use the stack to route packets after
	// the packet is decrypted so set skb->mark to zero from XFRM stack
	// to avoid confusion in netfilters and conntrack that may be using
	// the mark fields. This uses XFRM_OUTPUT_MARK added in 4.14 kernels.
	zeroMark := option.Config.EnableEndpointRoutes

	return errors.Join(
		errs,
		n.enableIPsecIPv4(newNode, nodeID, zeroMark),
		n.enableIPsecIPv6(newNode, nodeID, zeroMark),
	)
}

func (n *linuxNodeHandler) enableIPsecIPv4(newNode *nodeTypes.Node, nodeID uint16, zeroMark bool) error {
	var spi uint8
	var errs error

	if !n.nodeConfig.EnableIPv4 || (newNode.IPv4AllocCIDR == nil && !n.subnetEncryption()) {
		return nil
	}

	wildcardIP := net.ParseIP(wildcardIPv4)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.IPv4Mask(0, 0, 0, 0)}

	err := ipsec.IPsecDefaultDropPolicy(false)
	errs = errors.Join(errs, upsertIPsecLog(err, "default-drop IPv4", wildcardCIDR, wildcardCIDR, spi, 0))

	if newNode.IsLocal() {
		localIP := newNode.GetCiliumInternalIP(false)
		if localIP == nil {
			return errs
		}

		if n.subnetEncryption() {
			// FIXME: Remove the following four lines in Cilium v1.16
			if localCIDR := n.nodeAddressing.IPv4().AllocationCIDR(); localCIDR != nil {
				// This removes a bogus route that Cilium installed prior to v1.15
				_ = route.Delete(n.createNodeIPSecInRoute(localCIDR.IPNet))
			}

			localNodeInternalIP, err := getV4LinkLocalIP()
			if err != nil {
				log.WithError(err).Error("Failed to get local IPv4 for IPsec configuration")
				errs = errors.Join(errs, fmt.Errorf("failed to get local ipv4 for ipsec link: %w", err))
			}

			for _, cidr := range n.nodeConfig.IPv4PodSubnets {
				/* Insert wildcard policy rules for traffic skipping back through host */
				if err = ipsec.IpSecReplacePolicyFwd(cidr, localIP); err != nil {
					log.WithError(err).Warning("egress unable to replace policy fwd:")
				}

				spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in CiliumInternalIPv4", wildcardCIDR, cidr, spi, 0))

				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localNodeInternalIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in NodeInternalIPv4", wildcardCIDR, cidr, spi, 0))
			}
		} else {
			/* Insert wildcard policy rules for traffic skipping back through host */
			if err = ipsec.IpSecReplacePolicyFwd(wildcardCIDR, localIP); err != nil {
				log.WithError(err).Warning("egress unable to replace policy fwd:")
			}

			localCIDR := n.nodeAddressing.IPv4().AllocationCIDR().IPNet
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(localCIDR))
			spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, wildcardIP, 0, ipsec.IPSecDirIn, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "in IPv4", localCIDR, wildcardCIDR, spi, 0))
		}
	} else {
		remoteIP := newNode.GetCiliumInternalIP(false)
		if remoteIP == nil {
			return errs
		}

		localIP := n.nodeAddressing.IPv4().Router()

		if n.subnetEncryption() {
			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP, err = getV4LinkLocalIP()
				if err != nil {
					log.WithError(err).Error("Failed to get local IPv4 for IPsec configuration")
				}
				remoteIP = newNode.GetNodeIP(false)
			}

			for _, cidr := range n.nodeConfig.IPv4PodSubnets {
				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "out IPv4", wildcardCIDR, cidr, spi, nodeID))
			}
		} else {
			remoteCIDR := newNode.IPv4AllocCIDR.IPNet
			n.replaceNodeIPSecOutRoute(remoteCIDR)
			spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "out IPv4", wildcardCIDR, remoteCIDR, spi, nodeID))
		}
	}
	return errs
}

func (n *linuxNodeHandler) enableIPsecIPv6(newNode *nodeTypes.Node, nodeID uint16, zeroMark bool) error {
	var errs error
	var spi uint8

	if !n.nodeConfig.EnableIPv6 || (newNode.IPv6AllocCIDR == nil && !n.subnetEncryption()) {
		return nil
	}

	wildcardIP := net.ParseIP(wildcardIPv6)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.CIDRMask(0, 128)}

	err := ipsec.IPsecDefaultDropPolicy(true)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to create default drop policy IPv6: %w", err))
	}
	errs = errors.Join(errs, upsertIPsecLog(err, "default-drop IPv6", wildcardCIDR, wildcardCIDR, spi, 0))

	if newNode.IsLocal() {
		localIP := newNode.GetCiliumInternalIP(true)
		if localIP == nil {
			return errs
		}

		if n.subnetEncryption() {
			// FIXME: Remove the following four lines in Cilium v1.16
			if localCIDR := n.nodeAddressing.IPv6().AllocationCIDR(); localCIDR != nil {
				// This removes a bogus route that Cilium installed prior to v1.15
				_ = route.Delete(n.createNodeIPSecInRoute(localCIDR.IPNet))
			}

			localNodeInternalIP, err := getV6LinkLocalIP()
			if err != nil {
				log.WithError(err).Error("Failed to get local IPv6 for IPsec configuration")
				errs = errors.Join(errs, fmt.Errorf("failed to get local ipv6 for ipsec link: %w", err))
			}

			for _, cidr := range n.nodeConfig.IPv6PodSubnets {
				spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in CiliumInternalIPv6", wildcardCIDR, cidr, spi, 0))

				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localNodeInternalIP, wildcardIP, 0, ipsec.IPSecDirIn, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "in NodeInternalIPv6", wildcardCIDR, cidr, spi, 0))
			}
		} else {
			localCIDR := n.nodeAddressing.IPv6().AllocationCIDR().IPNet
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(localCIDR))
			spi, err = ipsec.UpsertIPsecEndpoint(localCIDR, wildcardCIDR, localIP, wildcardIP, 0, ipsec.IPSecDirIn, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "in IPv6", localCIDR, wildcardCIDR, spi, 0))
		}
	} else {
		remoteIP := newNode.GetCiliumInternalIP(true)
		if remoteIP == nil {
			return errs
		}

		localIP := n.nodeAddressing.IPv6().Router()

		if n.subnetEncryption() {
			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP, err = getV6LinkLocalIP()
				if err != nil {
					log.WithError(err).Error("Failed to get local IPv6 for IPsec configuration")
					errs = errors.Join(errs, fmt.Errorf("failed to get local ipv6 for ipsec link: %w", err))
				}
				remoteIP = newNode.GetNodeIP(true)
			}

			for _, cidr := range n.nodeConfig.IPv6PodSubnets {
				spi, err = ipsec.UpsertIPsecEndpoint(wildcardCIDR, cidr, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, zeroMark)
				errs = errors.Join(errs, upsertIPsecLog(err, "out IPv6", wildcardCIDR, cidr, spi, nodeID))
			}
		} else {
			remoteCIDR := newNode.IPv6AllocCIDR.IPNet
			n.replaceNodeIPSecOutRoute(remoteCIDR)
			spi, err := ipsec.UpsertIPsecEndpoint(wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, ipsec.IPSecDirOut, false)
			errs = errors.Join(errs, upsertIPsecLog(err, "out IPv6", wildcardCIDR, remoteCIDR, spi, nodeID))
		}
	}
	return errs
}

func (n *linuxNodeHandler) subnetEncryption() bool {
	return len(n.nodeConfig.IPv4PodSubnets) > 0 || len(n.nodeConfig.IPv6PodSubnets) > 0
}

func (n *linuxNodeHandler) removeEncryptRules() error {
	rule := route.Rule{
		Priority: 1,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableIPSec,
		Protocol: linux_defaults.RTProto,
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("delete previous IPv4 decrypt rule failed: %w", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("delete previousa IPv4 encrypt rule failed: %w", err)
		}
	}

	if err := route.DeleteRouteTable(linux_defaults.RouteTableIPSec, netlink.FAMILY_V4); err != nil {
		log.WithError(err).Warn("Deletion of IPSec routes failed")
	}

	rule.Mark = linux_defaults.RouteMarkDecrypt
	if err := route.DeleteRule(netlink.FAMILY_V6, rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("delete previous IPv6 decrypt rule failed: %w", err)
		}
	}

	rule.Mark = linux_defaults.RouteMarkEncrypt
	if err := route.DeleteRule(netlink.FAMILY_V6, rule); err != nil {
		if !os.IsNotExist(err) && !errors.Is(err, unix.EAFNOSUPPORT) {
			return fmt.Errorf("delete previous IPv6 encrypt rule failed: %w", err)
		}
	}
	return nil
}

func (n *linuxNodeHandler) createNodeIPSecInRoute(ip *net.IPNet) route.Route {
	var device string

	if !option.Config.TunnelingEnabled() {
		device = option.Config.EncryptInterface[0]
	} else {
		device = n.datapathConfig.TunnelDevice
	}
	return route.Route{
		Nexthop: nil,
		Device:  device,
		Prefix:  *ip,
		Table:   linux_defaults.RouteTableIPSec,
		Proto:   linux_defaults.RTProto,
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
		Proto:   linux_defaults.RTProto,
	}
}

// replaceNodeIPSecOutRoute replace the out IPSec route in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecOutRoute(ip *net.IPNet) error {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Upsert(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route OUT the host routing table")
		return err
	}
	return nil
}

// The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) deleteNodeIPSecOutRoute(ip *net.IPNet) error {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Delete(n.createNodeIPSecOutRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to delete the IPsec route OUT from the host routing table")
		return fmt.Errorf("failed to delete ipsec host route out: %w", err)
	}
	return nil
}

// replaceNodeIPSecoInRoute replace the in IPSec routes in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecInRoute(ip *net.IPNet) error {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return nil
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return nil
		}
	}

	if err := route.Upsert(n.createNodeIPSecInRoute(ip)); err != nil {
		log.WithError(err).WithField(logfields.CIDR, ip).Error("Unable to replace the IPSec route IN the host routing table")
		return fmt.Errorf("failed to replace ipsec host route IN: %w", err)
	}
	return nil
}

func (n *linuxNodeHandler) deleteIPsec(oldNode *nodeTypes.Node) error {
	var errs error
	scopedLog := log.WithField(logfields.NodeName, oldNode.Name)
	scopedLog.Debugf("Removing IPsec configuration for node")

	nodeID := n.getNodeIDForNode(oldNode)
	if nodeID == 0 {
		scopedLog.Warning("No node ID found for node.")
	} else {
		errs = errors.Join(errs, ipsec.DeleteIPsecEndpoint(nodeID))
	}

	if n.nodeConfig.EnableIPv4 && oldNode.IPv4AllocCIDR != nil {
		old4RouteNet := &net.IPNet{IP: oldNode.IPv4AllocCIDR.IP, Mask: oldNode.IPv4AllocCIDR.Mask}
		// This is only needed in IPAM modes where we install one route per
		// remote pod CIDR.
		if !n.subnetEncryption() {
			errs = errors.Join(errs, n.deleteNodeIPSecOutRoute(old4RouteNet))
		}
	}

	if n.nodeConfig.EnableIPv6 && oldNode.IPv6AllocCIDR != nil {
		old6RouteNet := &net.IPNet{IP: oldNode.IPv6AllocCIDR.IP, Mask: oldNode.IPv6AllocCIDR.Mask}
		// See IPv4 case above.
		if !n.subnetEncryption() {
			n.deleteNodeIPSecOutRoute(old6RouteNet)
		}
	}
	return errs
}
