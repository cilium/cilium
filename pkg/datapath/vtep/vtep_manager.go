// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
)

type VTEPManager struct {
	logger  *slog.Logger
	vtepMap vtep.Map
}

func newVTEPManager(logger *slog.Logger, vtepMap vtep.Map) *VTEPManager {
	return &VTEPManager{
		logger:  logger,
		vtepMap: vtepMap,
	}
}

func (r *VTEPManager) SetupVTEPMapping() error {
	for i, ep := range option.Config.VtepEndpoints {
		r.logger.Debug(
			"Updating vtep map entry for VTEP",
			logfields.IPAddr, ep,
		)

		err := r.vtepMap.Update(option.Config.VtepCIDRs[i], ep, option.Config.VtepMACs[i])
		if err != nil {
			return fmt.Errorf("Unable to set up VTEP ipcache mappings: %w", err)
		}
	}
	return nil
}

func (r *VTEPManager) SetupRouteToVtepCidr() error {
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

	addedVtepRoutes, removedVtepRoutes := cidr.DiffCIDRLists(routeCidrs, option.Config.VtepCIDRs)
	vtepMTU := mtu.EthernetMTU - mtu.TunnelOverheadIPv4

	if option.Config.EnableL7Proxy {
		for _, prefix := range addedVtepRoutes {
			ip4 := prefix.IP.To4()
			if ip4 == nil {
				return fmt.Errorf("Invalid VTEP CIDR IPv4 address: %v", ip4)
			}
			rt := route.Route{
				Device: defaults.HostDevice,
				Prefix: *prefix.IPNet,
				Scope:  netlink.SCOPE_LINK,
				MTU:    vtepMTU,
				Table:  linux_defaults.RouteTableVtep,
			}
			if err := route.Upsert(r.logger, rt); err != nil {
				return fmt.Errorf("Update VTEP CIDR route error: %w", err)
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
				return fmt.Errorf("Update VTEP CIDR rule error: %w", err)
			}
		}
	} else {
		removedVtepRoutes = routeCidrs
	}

	for _, prefix := range removedVtepRoutes {
		ip4 := prefix.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("Invalid VTEP CIDR IPv4 address: %v", ip4)
		}
		rt := route.Route{
			Device: defaults.HostDevice,
			Prefix: *prefix.IPNet,
			Scope:  netlink.SCOPE_LINK,
			MTU:    vtepMTU,
			Table:  linux_defaults.RouteTableVtep,
		}
		if err := route.Delete(rt); err != nil {
			return fmt.Errorf("Delete VTEP CIDR route error: %w", err)
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
			return fmt.Errorf("Delete VTEP CIDR rule error: %w", err)
		}
	}

	return nil
}
