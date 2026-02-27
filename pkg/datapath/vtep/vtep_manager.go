// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
)

type vtepManagerConfig struct {
	vtepCIDRs []*cidr.CIDR
}

// vtepManager handles Linux route/rule management for VTEP CIDRs.
// Its config field is only accessed from VTEPReconciler.syncDesiredStateLocked,
// which is serialized by VTEPReconciler.mu. Do not access config from other goroutines.
type vtepManager struct {
	logger *slog.Logger
	config vtepManagerConfig
}

func (r *vtepManager) setupRouteToVTEPCidr() error {
	routeCidrs := []*cidr.CIDR{}

	filter := &netlink.Route{
		Table: linux_defaults.RouteTableVtep,
	}

	routes, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}
	for _, rt := range routes {
		rtCIDR, err := cidr.ParseCIDR(rt.Dst.String())
		if err != nil {
			return fmt.Errorf("Invalid VTEP Route CIDR: %w", err)
		}
		routeCidrs = append(routeCidrs, rtCIDR)
	}

	addedVtepRoutes, removedVtepRoutes := cidr.DiffCIDRLists(routeCidrs, r.config.vtepCIDRs)
	vtepMTU := mtu.EthernetMTU - mtu.TunnelOverheadIPv4

	var errs []error

	if option.Config.EnableL7Proxy {
		for _, prefix := range addedVtepRoutes {
			ip4 := prefix.IP.To4()
			if ip4 == nil {
				errs = append(errs, fmt.Errorf("invalid VTEP CIDR IPv4 address: %v", prefix.IP))
				continue
			}
			rt := route.Route{
				Device: defaults.HostDevice,
				Prefix: *prefix.IPNet,
				Scope:  netlink.SCOPE_LINK,
				MTU:    vtepMTU,
				Table:  linux_defaults.RouteTableVtep,
			}
			if err := route.Upsert(r.logger, rt); err != nil {
				errs = append(errs, fmt.Errorf("update VTEP CIDR route error: %w", err))
				continue
			}
			r.logger.Info(
				"VTEP route added",
				logfields.IPAddr, rt.Prefix,
			)

			rule := route.Rule{
				Priority: linux_defaults.RulePriorityVtep,
				To:       prefix.IPNet,
				Table:    linux_defaults.RouteTableVtep,
			}
			if err := route.ReplaceRule(rule); err != nil {
				errs = append(errs, fmt.Errorf("update VTEP CIDR rule error: %w", err))
			}
		}
	} else {
		removedVtepRoutes = routeCidrs
	}

	for _, prefix := range removedVtepRoutes {
		ip4 := prefix.IP.To4()
		if ip4 == nil {
			errs = append(errs, fmt.Errorf("invalid VTEP CIDR IPv4 address: %v", prefix.IP))
			continue
		}
		rt := route.Route{
			Device: defaults.HostDevice,
			Prefix: *prefix.IPNet,
			Scope:  netlink.SCOPE_LINK,
			MTU:    vtepMTU,
			Table:  linux_defaults.RouteTableVtep,
		}
		if err := route.Delete(rt); err != nil {
			errs = append(errs, fmt.Errorf("delete VTEP CIDR route error: %w", err))
			continue
		}
		r.logger.Info(
			"VTEP route removed",
			logfields.IPAddr, rt.Prefix,
		)

		rule := route.Rule{
			Priority: linux_defaults.RulePriorityVtep,
			To:       prefix.IPNet,
			Table:    linux_defaults.RouteTableVtep,
		}
		if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
			errs = append(errs, fmt.Errorf("delete VTEP CIDR rule error: %w", err))
		}
	}

	return errors.Join(errs...)
}
