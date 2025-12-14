// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// Routing rule for traffic to proxy.
	toProxyRule = route.Rule{
		// Cilium bumps the default catch-all pref 0 routing rule that points at
		// table 255 to pref 100 during startup, to create space to insert its own
		// rules between 0-99.
		Priority: linux_defaults.RulePriorityToProxyIngress,
		Mark:     linux_defaults.MagicMarkIsToProxy,
		Mask:     linux_defaults.MagicMarkHostMask,
		Table:    linux_defaults.RouteTableToProxy,
		Protocol: linux_defaults.RTProto,
	}
)

// ReinstallRoutingRules ensures the presence of routing rules and tables needed
// to route packets to and from the L7 proxy. Or removes rules if the proxy is disabled.
func (p *Proxy) ReinstallRoutingRules(ctx context.Context, mtu int, ipsecEnabled, wireguardEnabled bool) error {
	defer p.routeManager.FinalizeInitializer(p.routeInitializer)

	localNode, err := p.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve local node: %w", err)
	}

	fromIngressProxy, fromEgressProxy, mtu := requireFromProxyRoutes(ipsecEnabled, wireguardEnabled, mtu)

	rxn := p.db.ReadTxn()
	hostDevice, _, hostDeviceFound := p.devices.Get(rxn, tables.DeviceNameIndex.Query(defaults.HostDevice))
	lo, _, loFound := p.devices.Get(rxn, tables.DeviceNameIndex.Query("lo"))

	if option.Config.EnableIPv4 && p.enabled {
		if !loFound {
			return fmt.Errorf("failed to get loopback device")
		}
		if err := installToProxyRoutesIPv4(lo, p.routeManager, p.routeOwner); err != nil {
			return err
		}

		if fromIngressProxy || fromEgressProxy {
			if !hostDeviceFound {
				return fmt.Errorf("failed to get host device %s", defaults.HostDevice)
			}
			internalIP, _ := netipx.FromStdIP(localNode.GetCiliumInternalIP(false))
			if err := installFromProxyRoutesIPv4(p.routeManager, p.routeOwner, internalIP, hostDevice, fromIngressProxy, fromEgressProxy, mtu); err != nil {
				return err
			}
		} else {
			if err := removeFromProxyRulesIPv4(); err != nil {
				return err
			}
		}
	} else {
		if err := removeToProxyRulesIPv4(); err != nil {
			return err
		}
		if err := removeFromProxyRulesIPv4(); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 && p.enabled {
		if err := installToProxyRulesIPv6(lo, p.routeManager, p.routeOwner); err != nil {
			return err
		}

		if fromIngressProxy || fromEgressProxy {
			ipv6, err := getCiliumNetIPv6()
			if err != nil {
				return err
			}
			if !hostDeviceFound {
				return fmt.Errorf("failed to get host device %s", defaults.HostDevice)
			}
			netIP, _ := netipx.FromStdIP(ipv6)
			if err := installFromProxyRoutesIPv6(p.routeOwner, p.routeManager, netIP, hostDevice, fromIngressProxy, fromEgressProxy, mtu); err != nil {
				return err
			}
		} else {
			if err := removeFromProxyRulesIPv6(); err != nil {
				return err
			}
		}
	} else {
		if err := removeToProxyRulesIPv6(); err != nil {
			return err
		}
		if err := removeFromProxyRulesIPv6(); err != nil {
			return err
		}
	}

	return nil
}

// requireFromProxyRoutes determines whether routes from the proxy are needed,
// and selects the appropriate MTU to set on those routes.
//
// Conditions for proxy routes:
//   - Native routing + Envoy: install only Ingress routes to handle reply packet of
//     hair-pinning traffic in Ingress L7 proxy (i.e. backend is in the same node).
//   - Native routing + IPSec: install Ingress+Egress routes for (a) the same reason
//     as above, and also to account for XFRM overhead on proxy-to-proxy connections.
//   - Native routing + WireGuard: install only Ingress routes to account for WireGuard
//     overhead on reply packets from Ingress L7 proxy in proxy-to-proxy connections.
func requireFromProxyRoutes(ipsecEnabled, wireguardEnabled bool, mtuIn int) (fromIngressProxy, fromEgressProxy bool, mtu int) {
	if option.Config.TunnelingEnabled() {
		return
	}
	if option.Config.EnableEnvoyConfig {
		fromIngressProxy = true
	}
	switch {
	case ipsecEnabled:
		fromIngressProxy = true
		fromEgressProxy = true
		mtu = mtuIn
	case wireguardEnabled:
		fromIngressProxy = true
		mtu = mtuIn
	}
	return
}

// getCiliumNetIPv6 retrieves the first IPv6 address from the cilium_net device.
func getCiliumNetIPv6() (net.IP, error) {
	link, err := safenetlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return nil, fmt.Errorf("cannot find link '%s': %w", defaults.SecondHostDevice, err)
	}

	addrList, err := safenetlink.AddrList(link, netlink.FAMILY_V6)
	if err == nil && len(addrList) > 0 {
		return addrList[0].IP, nil
	}

	return nil, fmt.Errorf("failed to find valid IPv6 address for cilium_net")
}

// installToProxyRoutesIPv4 configures routes and rules needed to redirect ingress
// packets to the proxy.
func installToProxyRoutesIPv4(loDevice *tables.Device, routeManager *reconciler.DesiredRouteManager, routeOwner *reconciler.RouteOwner) error {
	route4 := reconciler.DesiredRoute{
		Owner:         routeOwner,
		Table:         linux_defaults.RouteTableToProxy,
		Prefix:        netip.MustParsePrefix("0.0.0.0/0"),
		AdminDistance: reconciler.AdminDistanceDefault,
		Type:          reconciler.RTN_LOCAL,
		Src:           netip.AddrFrom4([4]byte{}),
		Device:        loDevice,
	}

	if err := routeManager.UpsertRouteWait(route4); err != nil {
		return fmt.Errorf("inserting ipv4 proxy route %v: %w", route4, err)
	}
	if err := route.ReplaceRule(toProxyRule); err != nil {
		return fmt.Errorf("inserting ipv4 proxy routing rule %v: %w", toProxyRule, err)
	}

	return nil
}

// removeToProxyRulesIPv4 ensures routes and rules for proxy traffic are removed.
func removeToProxyRulesIPv4() error {
	if err := route.DeleteRule(netlink.FAMILY_V4, toProxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv4 proxy routing rule: %w", err)
	}

	return nil
}

// installToProxyRulesIPv6 configures routes and rules needed to redirect ingress
// packets to the proxy.
func installToProxyRulesIPv6(loDevice *tables.Device, routeManager *reconciler.DesiredRouteManager, routeOwner *reconciler.RouteOwner) error {
	route6 := reconciler.DesiredRoute{
		Owner:         routeOwner,
		Table:         linux_defaults.RouteTableToProxy,
		Prefix:        netip.MustParsePrefix("::/0"),
		AdminDistance: reconciler.AdminDistanceDefault,
		Type:          route.RTN_LOCAL,
		Src:           netip.AddrFrom16([16]byte{}),
		Device:        loDevice,
	}

	if err := routeManager.UpsertRouteWait(route6); err != nil {
		return fmt.Errorf("inserting ipv6 proxy route %v: %w", route6, err)
	}
	if err := route.ReplaceRuleIPv6(toProxyRule); err != nil {
		return fmt.Errorf("inserting ipv6 proxy routing rule %v: %w", toProxyRule, err)
	}

	return nil
}

// removeToProxyRulesIPv6 ensures routes and rules for proxy traffic are removed.
func removeToProxyRulesIPv6() error {
	if err := route.DeleteRule(netlink.FAMILY_V6, toProxyRule); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return fmt.Errorf("removing ipv6 proxy routing rule: %w", err)
		}
	}

	return nil
}

var (
	// Routing rule for traffic from ingress proxy.
	fromIngressProxyRule = route.Rule{
		Priority: linux_defaults.RulePriorityFromProxy,
		Mark:     linux_defaults.MagicMarkIngress,
		Mask:     linux_defaults.MagicMarkHostMask,
		Table:    linux_defaults.RouteTableFromProxy,
		Protocol: linux_defaults.RTProto,
	}

	// Routing rule for traffic from egress proxy.
	fromEgressProxyRule = route.Rule{
		Priority: linux_defaults.RulePriorityFromProxy,
		Mark:     linux_defaults.MagicMarkEgress,
		Mask:     linux_defaults.MagicMarkHostMask,
		Table:    linux_defaults.RouteTableFromProxy,
		Protocol: linux_defaults.RTProto,
	}
)

// installFromProxyRoutesIPv4 configures routes and rules needed to redirect ingress
// packets from the proxy.
func installFromProxyRoutesIPv4(
	routeManager *reconciler.DesiredRouteManager,
	routeOwner *reconciler.RouteOwner,
	ipv4 netip.Addr,
	device *tables.Device,
	fromIngressProxy, fromEgressProxy bool,
	mtu int,
) error {
	prefix, _ := ipv4.Prefix(ipv4.BitLen())
	fromProxyToCiliumHostRoute4 := reconciler.DesiredRoute{
		Owner:         routeOwner,
		Table:         linux_defaults.RouteTableFromProxy,
		Prefix:        prefix,
		AdminDistance: reconciler.AdminDistanceDefault,

		Device: device,
		Scope:  reconciler.Scope(netlink.SCOPE_LINK),
	}
	fromProxyDefaultRoute4 := reconciler.DesiredRoute{
		Owner:         routeOwner,
		Table:         linux_defaults.RouteTableFromProxy,
		Prefix:        netip.MustParsePrefix("0.0.0.0/0"),
		AdminDistance: reconciler.AdminDistanceDefault,

		Nexthop: ipv4,
		Device:  device,
		MTU:     uint32(mtu),
	}

	if fromIngressProxy {
		if err := route.ReplaceRule(fromIngressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv4 from ingress proxy routing rule %v: %w", fromIngressProxyRule, err)
		}
	}
	if fromEgressProxy {
		if err := route.ReplaceRule(fromEgressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv4 from egress proxy routing rule %v: %w", fromEgressProxyRule, err)
		}
	}
	if err := routeManager.UpsertRouteWait(fromProxyToCiliumHostRoute4); err != nil {
		return fmt.Errorf("inserting ipv4 from proxy to cilium_host route %v: %w", fromProxyToCiliumHostRoute4, err)
	}
	if err := routeManager.UpsertRouteWait(fromProxyDefaultRoute4); err != nil {
		return fmt.Errorf("inserting ipv4 from proxy default route %v: %w", fromProxyDefaultRoute4, err)
	}

	return nil
}

// removeFromProxyRulesIPv4 ensures routes and rules for traffic from the proxy are removed.
func removeFromProxyRulesIPv4() error {
	if err := route.DeleteRule(netlink.FAMILY_V4, fromIngressProxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv4 from ingress proxy routing rule: %w", err)
	}
	if err := route.DeleteRule(netlink.FAMILY_V4, fromEgressProxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv4 from egress proxy routing rule: %w", err)
	}

	return nil
}

// installFromProxyRoutesIPv6 configures routes and rules needed to redirect ingress
// packets from the proxy.
func installFromProxyRoutesIPv6(
	routeOwner *reconciler.RouteOwner,
	routeManager *reconciler.DesiredRouteManager,
	ipv6 netip.Addr,
	device *tables.Device,
	fromIngressProxy, fromEgressProxy bool,
	mtu int,
) error {
	prefix, _ := ipv6.Prefix(ipv6.BitLen())
	fromProxyToCiliumHostRoute6 := reconciler.DesiredRoute{
		Owner:         routeOwner,
		Table:         linux_defaults.RouteTableFromProxy,
		Prefix:        prefix,
		AdminDistance: reconciler.AdminDistanceDefault,

		Device: device,
	}

	fromProxyDefaultRoute6 := reconciler.DesiredRoute{
		Owner:         routeOwner,
		Table:         linux_defaults.RouteTableFromProxy,
		Prefix:        netip.MustParsePrefix("::/0"),
		AdminDistance: reconciler.AdminDistanceDefault,

		Nexthop: ipv6,
		Device:  device,
		MTU:     uint32(mtu),
	}

	if fromIngressProxy {
		if err := route.ReplaceRuleIPv6(fromIngressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv6 from ingress proxy routing rule %v: %w", fromIngressProxyRule, err)
		}
	}
	if fromEgressProxy {
		if err := route.ReplaceRuleIPv6(fromEgressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv6 from egress proxy routing rule %v: %w", fromEgressProxyRule, err)
		}
	}
	if err := routeManager.UpsertRouteWait(fromProxyToCiliumHostRoute6); err != nil {
		return fmt.Errorf("inserting ipv6 from proxy to cilium_host route %v: %w", fromProxyToCiliumHostRoute6, err)
	}
	if err := routeManager.UpsertRouteWait(fromProxyDefaultRoute6); err != nil {
		return fmt.Errorf("inserting ipv6 from proxy default route %v: %w", fromProxyDefaultRoute6, err)
	}

	return nil
}

// removeFromProxyRulesIPv6 ensures routes and rules for traffic from the proxy are removed.
func removeFromProxyRulesIPv6() error {
	if err := route.DeleteRule(netlink.FAMILY_V6, fromIngressProxyRule); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return fmt.Errorf("removing ipv6 from ingress proxy routing rule: %w", err)
		}
	}
	if err := route.DeleteRule(netlink.FAMILY_V6, fromEgressProxyRule); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return fmt.Errorf("removing ipv6 from egress proxy routing rule: %w", err)
		}
	}

	return nil
}
