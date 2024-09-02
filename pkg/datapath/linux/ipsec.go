// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

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

var (
	exactMatchMask = net.IPv4Mask(255, 255, 255, 255)
)

// getDefaultEncryptionInterface() is needed to find the interface used when
// populating neighbor table and doing arpRequest. For most configurations
// there is only a single interface so choosing [0] works by choosing the only
// interface. However EKS, uses multiple interfaces, but fortunately for us
// in EKS any interface would work so pick the [0] index here as well.
func (n *linuxNodeHandler) getDefaultEncryptionInterface() string {
	if option.Config.TunnelingEnabled() {
		return n.datapathConfig.TunnelDevice
	}
	devices := n.nodeConfig.Devices
	if len(devices) > 0 {
		return devices[0].Name
	}
	if len(option.Config.EncryptInterface) > 0 {
		return option.Config.EncryptInterface[0]
	}
	return ""
}

func (n *linuxNodeHandler) getLinkLocalIP(family int) (net.IP, error) {
	iface := n.getDefaultEncryptionInterface()
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	addr, err := netlink.AddrList(link, family)
	if err != nil {
		return nil, err
	}
	if len(addr) == 0 {
		return nil, fmt.Errorf("error retrieving link local IP (family %d): no addresses found", family)
	}
	return addr[0].IPNet.IP, nil
}

func (n *linuxNodeHandler) getV4LinkLocalIP() (net.IP, error) {
	return n.getLinkLocalIP(netlink.FAMILY_V4)
}

func (n *linuxNodeHandler) getV6LinkLocalIP() (net.IP, error) {
	return n.getLinkLocalIP(netlink.FAMILY_V6)
}

func upsertIPsecLog(log *slog.Logger, err error, spec string, loc, rem *net.IPNet, spi uint8, nodeID uint16) error {
	scopedLog := log.With(
		logfields.Reason, spec,
		logfields.SPI, spi,
		logfields.LocalIP, loc,
		logfields.RemoteIP, rem,
		logfields.NodeID, fmt.Sprintf("0x%x", nodeID),
	)
	if err != nil {
		scopedLog.Error("IPsec enable failed", logfields.Error, err)
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
			n.log.Error("IPSec metrics registration failed. No metrics will be reported!",
				logfields.Error, err,
			)
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

func (n *linuxNodeHandler) enableIPsec(oldNode, newNode *nodeTypes.Node, nodeID uint16) error {
	var errs error
	if newNode.IsLocal() {
		if err := n.replaceHostRules(); err != nil {
			errs = fmt.Errorf("failed to replace host rules: %w", err)
		}
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
		update, err := n.enableIPsecIPv4(newNode, nodeID, zeroMark, updateExisting)
		statesUpdated = statesUpdated && update
		errs = errors.Join(errs, err)
	}
	if n.nodeConfig.EnableIPv6 && (newNode.IPv6AllocCIDR != nil || n.subnetEncryption()) {
		update, err := n.enableIPsecIPv6(newNode, nodeID, zeroMark, updateExisting)
		statesUpdated = statesUpdated && update
		errs = errors.Join(errs, err)
	}

	if updateExisting && statesUpdated {
		delete(n.ipsecUpdateNeeded, newNode.Identity())
	}

	return errs
}

func (n *linuxNodeHandler) enableIPsecIPv4(newNode *nodeTypes.Node, nodeID uint16, zeroMark, updateExisting bool) (bool, error) {
	statesUpdated := true
	var spi uint8
	var errs error

	wildcardIP := net.ParseIP(wildcardIPv4)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.IPv4Mask(0, 0, 0, 0)}

	err := ipsec.IPsecDefaultDropPolicy(n.log, false)
	errs = errors.Join(errs, upsertIPsecLog(n.log, err, "default-drop IPv4", wildcardCIDR, wildcardCIDR, spi, 0))

	if newNode.IsLocal() {
		if !n.subnetEncryption() {
			localCIDR := n.nodeConfig.AllocCIDRIPv4.IPNet
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(localCIDR))
		}
	} else {
		// A node update that doesn't contain a BootID will cause the creation
		// of non-matching XFRM IN and OUT states across the cluster as the
		// BootID is used to generate per-node key pairs. Non-matching XFRM
		// states will result in XfrmInStateProtoError, causing packet drops.
		// An empty BootID should thus be treated as an error, and Cilium
		// should not attempt to derive per-node keys from it.
		if newNode.BootID == "" {
			n.log.Debug("Unable to enable IPsec for node with empty BootID", logfields.Node, newNode.Name)
			return false, errs
		}

		remoteCiliumInternalIP := newNode.GetCiliumInternalIP(false)
		if remoteCiliumInternalIP == nil {
			return false, errs
		}
		remoteIP := remoteCiliumInternalIP

		localCiliumInternalIP := n.nodeConfig.CiliumInternalIPv4
		localIP := localCiliumInternalIP

		if n.subnetEncryption() {
			localNodeInternalIP, err := n.getV4LinkLocalIP()
			if err != nil {
				n.log.Error("Failed to get local IPv4 for IPsec configuration", logfields.Error, err)
				errs = errors.Join(errs, fmt.Errorf("failed to get local ipv4 for ipsec link: %w", err))
			}
			remoteNodeInternalIP := newNode.GetNodeIP(false)

			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP = localNodeInternalIP
				remoteIP = remoteNodeInternalIP
			}

			for _, cidr := range n.nodeConfig.GetIPv4PodSubnets() {
				spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, cidr, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, zeroMark, updateExisting, ipsec.DefaultReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "out IPv4", wildcardCIDR, cidr, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}

				/* Insert wildcard policy rules for traffic skipping back through host */
				if err = ipsec.IpSecReplacePolicyFwd(cidr, localIP, ipsec.DefaultReqID); err != nil {
					n.log.Warn("egress unable to replace policy fwd", logfields.Error, err)
				}

				spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, cidr, localCiliumInternalIP, remoteCiliumInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting, ipsec.DefaultReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "in CiliumInternalIPv4", wildcardCIDR, cidr, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}

				spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, cidr, localNodeInternalIP, remoteNodeInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting, ipsec.DefaultReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "in NodeInternalIPv4", wildcardCIDR, cidr, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}
			}
		} else {
			localCIDR := n.nodeConfig.AllocCIDRIPv4.IPNet
			remoteCIDR := newNode.IPv4AllocCIDR.IPNet
			if err := n.replaceNodeIPSecOutRoute(remoteCIDR); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec OUT (%q): %w", remoteCIDR.IP, err))
			}
			spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, false, updateExisting, ipsec.DefaultReqID)
			errs = errors.Join(errs, upsertIPsecLog(n.log, err, "out IPv4", wildcardCIDR, remoteCIDR, spi, nodeID))
			if err != nil {
				statesUpdated = false
			}

			/* Insert wildcard policy rules for traffic skipping back through host */
			if err = ipsec.IpSecReplacePolicyFwd(wildcardCIDR, localIP, ipsec.DefaultReqID); err != nil {
				n.log.Warn("egress unable to replace policy fwd", logfields.Error, err)
			}

			spi, err = ipsec.UpsertIPsecEndpoint(n.log, localCIDR, wildcardCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, false, updateExisting, ipsec.DefaultReqID)
			errs = errors.Join(errs, upsertIPsecLog(n.log, err, "in IPv4", localCIDR, wildcardCIDR, spi, nodeID))
			if err != nil {
				statesUpdated = false
			}

			// In Encrypt Overlay mode, outermost header is ESP tunnel.
			// Packet format : [IP|ESP|IP|VxLAN|<payload>]
			// ESP tunnel src/dst addresses are underlay IPs of the node (NodeInternalIP).
			// VxLAN tunnel src/dst addresses are also underlay IPs of the node (NodeInternalIP).
			if n.nodeConfig.EnableIPSecEncryptedOverlay {
				localUnderlayIP := n.nodeConfig.NodeIPv4
				if localUnderlayIP == nil {
					n.log.Warn("unable to enable encrypted overlay IPsec, nil local internal IP")
					return false, errs
				}
				remoteUnderlayIP := newNode.GetNodeIP(false)
				if remoteUnderlayIP == nil {
					n.log.Warn("unable to enable encrypted overlay IPsec, nil remote internal IP for node", logfields.Node, newNode.Name)
					return false, errs
				}

				localOverlayIPExactMatch := &net.IPNet{IP: localUnderlayIP, Mask: exactMatchMask}
				remoteOverlayIPExactMatch := &net.IPNet{IP: remoteUnderlayIP, Mask: exactMatchMask}

				spi, err = ipsec.UpsertIPsecEndpoint(n.log, localOverlayIPExactMatch, remoteOverlayIPExactMatch, localUnderlayIP, remoteUnderlayIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, false, updateExisting, ipsec.EncryptedOverlayReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "overlay out IPv4", localOverlayIPExactMatch, remoteOverlayIPExactMatch, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}

				spi, err = ipsec.UpsertIPsecEndpoint(n.log, localOverlayIPExactMatch, remoteOverlayIPExactMatch, localUnderlayIP, remoteUnderlayIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, false, updateExisting, ipsec.EncryptedOverlayReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "overlay in IPv4", localOverlayIPExactMatch, remoteOverlayIPExactMatch, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}
			}
		}
	}
	return statesUpdated, errs
}

func (n *linuxNodeHandler) enableIPsecIPv6(newNode *nodeTypes.Node, nodeID uint16, zeroMark, updateExisting bool) (bool, error) {
	statesUpdated := true
	var errs error
	var spi uint8

	wildcardIP := net.ParseIP(wildcardIPv6)
	wildcardCIDR := &net.IPNet{IP: wildcardIP, Mask: net.CIDRMask(0, 128)}

	err := ipsec.IPsecDefaultDropPolicy(n.log, true)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to create default drop policy IPv6: %w", err))
	}
	errs = errors.Join(errs, upsertIPsecLog(n.log, err, "default-drop IPv6", wildcardCIDR, wildcardCIDR, spi, 0))

	if newNode.IsLocal() {
		if !n.subnetEncryption() {
			localCIDR := n.nodeConfig.AllocCIDRIPv6.IPNet
			errs = errors.Join(errs, n.replaceNodeIPSecInRoute(localCIDR))
		}
	} else {
		// A node update that doesn't contain a BootID will cause the creation
		// of non-matching XFRM IN and OUT states across the cluster as the
		// BootID is used to generate per-node key pairs. Non-matching XFRM
		// states will result in XfrmInStateProtoError, causing packet drops.
		// An empty BootID should thus be treated as an error, and Cilium
		// should not attempt to derive per-node keys from it.
		if newNode.BootID == "" {
			n.log.Debug("Unable to enable IPsec for node with empty BootID", logfields.Node, newNode.Name)
			return false, errs
		}

		remoteCiliumInternalIP := newNode.GetCiliumInternalIP(true)
		if remoteCiliumInternalIP == nil {
			return false, errs
		}
		remoteIP := remoteCiliumInternalIP

		localCiliumInternalIP := n.nodeConfig.CiliumInternalIPv6
		localIP := localCiliumInternalIP

		if n.subnetEncryption() {
			localNodeInternalIP, err := n.getV6LinkLocalIP()
			if err != nil {
				n.log.Error("Failed to get local IPv6 for IPsec configuration", logfields.Error, err)
				errs = errors.Join(errs, fmt.Errorf("failed to get local ipv6 for ipsec link: %w", err))
			}
			remoteNodeInternalIP := newNode.GetNodeIP(true)

			// Check if we should use the NodeInternalIPs instead of the
			// CiliumInternalIPs for the IPsec encapsulation.
			if !option.Config.UseCiliumInternalIPForIPsec {
				localIP = localNodeInternalIP
				remoteIP = remoteNodeInternalIP
			}

			for _, cidr := range n.nodeConfig.GetIPv6PodSubnets() {
				spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, cidr, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, zeroMark, updateExisting, ipsec.DefaultReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "out IPv6", wildcardCIDR, cidr, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}

				spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, cidr, localCiliumInternalIP, remoteCiliumInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting, ipsec.DefaultReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "in CiliumInternalIPv6", wildcardCIDR, cidr, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}

				spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, cidr, localNodeInternalIP, remoteNodeInternalIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, zeroMark, updateExisting, ipsec.DefaultReqID)
				errs = errors.Join(errs, upsertIPsecLog(n.log, err, "in NodeInternalIPv6", wildcardCIDR, cidr, spi, nodeID))
				if err != nil {
					statesUpdated = false
				}
			}
		} else {
			localCIDR := n.nodeConfig.AllocCIDRIPv6.IPNet
			remoteCIDR := newNode.IPv6AllocCIDR.IPNet
			if err := n.replaceNodeIPSecOutRoute(remoteCIDR); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to replace ipsec OUT (%q): %w", remoteCIDR.IP, err))
			}
			spi, err = ipsec.UpsertIPsecEndpoint(n.log, wildcardCIDR, remoteCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirOut, false, updateExisting, ipsec.DefaultReqID)
			errs = errors.Join(errs, upsertIPsecLog(n.log, err, "out IPv6", wildcardCIDR, remoteCIDR, spi, nodeID))
			if err != nil {
				statesUpdated = false
			}

			spi, err = ipsec.UpsertIPsecEndpoint(n.log, localCIDR, wildcardCIDR, localIP, remoteIP, nodeID, newNode.BootID, ipsec.IPSecDirIn, false, updateExisting, ipsec.DefaultReqID)
			errs = errors.Join(errs, upsertIPsecLog(n.log, err, "in IPv6", localCIDR, wildcardCIDR, spi, nodeID))
			if err != nil {
				statesUpdated = false
			}
		}
	}
	return statesUpdated, errs
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
			return fmt.Errorf("delete previous IPv4 encrypt rule failed: %w", err)
		}
	}

	if err := route.DeleteRouteTable(linux_defaults.RouteTableIPSec, netlink.FAMILY_V4); err != nil {
		n.log.Warn("Deletion of IPSec routes failed", logfields.Error, err)
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
	device := n.getDefaultEncryptionInterface()
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
		MTU:     n.nodeConfig.RoutePostEncryptMTU,
		Proto:   linux_defaults.RTProto,
	}
}

func (n *linuxNodeHandler) isValidIP(ip *net.IPNet) bool {
	if ip.IP.To4() != nil {
		if !n.nodeConfig.EnableIPv4 {
			return false
		}
	} else {
		if !n.nodeConfig.EnableIPv6 {
			return false
		}
	}

	return true
}

// replaceNodeIPSecOutRoute replace the out IPSec route in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecOutRoute(ip *net.IPNet) error {
	if !n.isValidIP(ip) {
		return nil
	}

	if err := route.Upsert(n.createNodeIPSecOutRoute(ip)); err != nil {
		n.log.Error("Unable to replace the IPSec route OUT the host routing table",
			logfields.Error, err,
			logfields.CIDR, ip,
		)
		return err
	}
	return nil
}

// The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) deleteNodeIPSecOutRoute(ip *net.IPNet) error {
	if !n.isValidIP(ip) {
		return nil
	}

	if err := route.Delete(n.createNodeIPSecOutRoute(ip)); err != nil {
		n.log.Error("Unable to delete the IPsec route OUT from the host routing table",
			logfields.Error, err,
			logfields.CIDR, ip,
		)
		return fmt.Errorf("failed to delete ipsec host route out: %w", err)
	}
	return nil
}

// replaceNodeIPSecoInRoute replace the in IPSec routes in the host routing
// table with the new route. If no route exists the route is installed on the
// host. The caller must ensure that the CIDR passed in must be non-nil.
func (n *linuxNodeHandler) replaceNodeIPSecInRoute(ip *net.IPNet) error {
	if !n.isValidIP(ip) {
		return nil
	}

	if err := route.Upsert(n.createNodeIPSecInRoute(ip)); err != nil {
		n.log.Error("Unable to replace the IPSec route IN the host routing table",
			logfields.Error, err,
			logfields.CIDR, ip,
		)
		return fmt.Errorf("failed to replace ipsec host route IN: %w", err)
	}
	return nil
}

func (n *linuxNodeHandler) deleteIPsec(oldNode *nodeTypes.Node) error {
	var errs error
	scopedLog := n.log.With(logfields.NodeName, oldNode.Name)
	scopedLog.Debug("Removing IPsec configuration for node")

	nodeID := n.getNodeIDForNode(oldNode)
	if nodeID == 0 {
		scopedLog.Warn("No node ID found for node.")
	} else {
		errs = errors.Join(errs, ipsec.DeleteIPsecEndpoint(n.log, nodeID))
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
			errs = errors.Join(errs, n.deleteNodeIPSecOutRoute(old6RouteNet))
		}
	}

	delete(n.ipsecUpdateNeeded, oldNode.Identity())

	return errs
}
