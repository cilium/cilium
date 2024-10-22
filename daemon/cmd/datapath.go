// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/ratelimitmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
)

// listFilterIfs returns a map of interfaces based on the given filter.
// The filter should take a link and, if found, return the index of that
// interface, if not found return -1.
func listFilterIfs(filter func(netlink.Link) int) (map[int]netlink.Link, error) {
	ifs, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if idx := filter(intf); idx != -1 {
			vethLXCIdxs[idx] = intf
		}
	}
	return vethLXCIdxs, nil
}

// clearCiliumVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func clearCiliumVeths() error {
	log.Info("Removing stale endpoint interfaces")

	leftVeths, err := listFilterIfs(func(intf netlink.Link) int {
		// Filter by veth and return the index of the interface.
		if intf.Type() == "veth" {
			return intf.Attrs().Index
		}
		return -1
	})
	if err != nil {
		return fmt.Errorf("unable to retrieve host network interfaces: %w", err)
	}

	for _, v := range leftVeths {
		peerIndex := v.Attrs().ParentIndex
		parentVeth, found := leftVeths[peerIndex]

		// In addition to name matching, double check whether the parent of the
		// parent is the interface itself, to avoid removing the interface in
		// case we hit an index clash, and the actual parent of the interface is
		// in a different network namespace. Notably, this can happen in the
		// context of Kind nodes, as eth0 is a veth interface itself; if an
		// lxcxxxxxx interface ends up having the same ifindex of the eth0 parent
		// (which is actually located in the root network namespace), we would
		// otherwise end up deleting the eth0 interface, with the obvious
		// ill-fated consequences.
		if found && peerIndex != 0 && strings.HasPrefix(parentVeth.Attrs().Name, "lxc") &&
			parentVeth.Attrs().ParentIndex == v.Attrs().Index {
			scopedlog := log.WithFields(logrus.Fields{
				logfields.Device: v.Attrs().Name,
			})

			scopedlog.Debug("Deleting stale veth device")
			err := netlink.LinkDel(v)
			if err != nil {
				scopedlog.WithError(err).Warning("Unable to delete stale veth device")
			}
		}
	}
	return nil
}

// EndpointMapManager is a wrapper around an endpointmanager as well as the
// filesystem for removing maps related to endpoints from the filesystem.
type EndpointMapManager struct {
	endpointmanager.EndpointManager
}

// RemoveDatapathMapping unlinks the endpointID from the global policy map, preventing
// packets that arrive on this node from being forwarded to the endpoint that
// used to exist with the specified ID.
func (e *EndpointMapManager) RemoveDatapathMapping(endpointID uint16) error {
	return policymap.RemoveGlobalMapping(uint32(endpointID), option.Config.EnableEnvoyConfig)
}

// RemoveMapPath removes the specified path from the filesystem.
func (e *EndpointMapManager) RemoveMapPath(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

// initMaps opens all BPF maps (and creates them if they do not exist). This
// must be done *before* any operations which read BPF maps, especially
// restoring endpoints and services.
func (d *Daemon) initMaps() error {
	if option.Config.DryMode {
		return nil
	}

	if err := lxcmap.LXCMap().OpenOrCreate(); err != nil {
		return fmt.Errorf("initializing lxc map: %w", err)
	}

	// The ipcache is shared between endpoints. Unpin the old ipcache map created
	// by any previous instances of the agent to prevent new endpoints from
	// picking up the old map pin. The old ipcache will continue to be used by
	// loaded bpf programs, it will just no longer be updated by the agent.
	//
	// This is to allow existing endpoints that have not been regenerated yet to
	// continue using the existing ipcache until the endpoint is regenerated for
	// the first time and its bpf programs have been replaced. Existing endpoints
	// are using a policy map which is potentially out of sync as local identities
	// are re-allocated on startup.
	if err := ipcachemap.IPCacheMap().Recreate(); err != nil {
		return fmt.Errorf("initializing ipcache map: %w", err)
	}

	if err := metricsmap.Metrics.OpenOrCreate(); err != nil {
		return fmt.Errorf("initializing metrics map: %w", err)
	}

	if err := ratelimitmap.InitMaps(); err != nil {
		return fmt.Errorf("initializing ratelimit maps: %w", err)
	}

	if option.Config.TunnelingEnabled() {
		if err := tunnel.TunnelMap().Recreate(); err != nil {
			return fmt.Errorf("initializing tunnel map: %w", err)
		}
	}

	if option.Config.EnableHighScaleIPcache {
		if err := worldcidrsmap.InitWorldCIDRsMap(); err != nil {
			return fmt.Errorf("initializing world CIDRs map: %w", err)
		}
	}

	if option.Config.EnableVTEP {
		if err := vtep.VtepMap().Recreate(); err != nil {
			return fmt.Errorf("initializing vtep map: %w", err)
		}
	}

	if err := d.svc.InitMaps(option.Config.EnableIPv6, option.Config.EnableIPv4,
		option.Config.EnableSocketLB, option.Config.RestoreState); err != nil {
		log.WithError(err).Fatal("Unable to initialize service maps")
	}

	if err := policymap.InitCallMaps(); err != nil {
		return fmt.Errorf("initializing policy map: %w", err)
	}

	for _, ep := range d.endpointManager.GetEndpoints() {
		ep.InitMap()
	}

	for _, ep := range d.endpointManager.GetEndpoints() {
		if !ep.ConntrackLocal() {
			continue
		}
		for _, m := range ctmap.LocalMaps(ep, option.Config.EnableIPv4,
			option.Config.EnableIPv6) {
			if err := m.Create(); err != nil {
				return fmt.Errorf("initializing conntrack map %s: %w", m.Name(), err)
			}
		}
	}
	for _, m := range ctmap.GlobalMaps(option.Config.EnableIPv4,
		option.Config.EnableIPv6) {
		if err := m.Create(); err != nil {
			return fmt.Errorf("initializing conntrack map %s: %w", m.Name(), err)
		}
	}

	ipv4Nat, ipv6Nat := nat.GlobalMaps(option.Config.EnableIPv4,
		option.Config.EnableIPv6, option.Config.EnableNodePort)
	if ipv4Nat != nil {
		if err := ipv4Nat.Create(); err != nil {
			return fmt.Errorf("initializing ipv4nat map: %w", err)
		}
	}
	if ipv6Nat != nil {
		if err := ipv6Nat.Create(); err != nil {
			return fmt.Errorf("initializing ipv6nat map: %w", err)
		}
	}

	if option.Config.EnableNodePort {
		if err := neighborsmap.InitMaps(option.Config.EnableIPv4,
			option.Config.EnableIPv6); err != nil {
			return fmt.Errorf("initializing neighbors map: %w", err)
		}
	}

	if option.Config.EnableIPv4FragmentsTracking {
		if err := fragmap.InitMap(option.Config.FragmentsMapEntries); err != nil {
			return fmt.Errorf("initializing fragments map: %w", err)
		}
	}

	if option.Config.EnableIPMasqAgent {
		if option.Config.EnableIPv4Masquerade {
			if err := ipmasq.IPMasq4Map().OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing IPv4 masquerading map: %w", err)
			}
		}
		if option.Config.EnableIPv6Masquerade {
			if err := ipmasq.IPMasq6Map().OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing IPv6 masquerading map: %w", err)
			}
		}
	}

	if option.Config.EnableIPSec {
		if err := encrypt.MapCreate(); err != nil {
			return fmt.Errorf("initializing IPsec map: %w", err)
		}
	}

	if !option.Config.RestoreState {
		// If we are not restoring state, all endpoints can be
		// deleted. Entries will be re-populated.
		lxcmap.LXCMap().DeleteAll()
	}

	if option.Config.EnableSessionAffinity {
		if err := lbmap.AffinityMatchMap.OpenOrCreate(); err != nil {
			return fmt.Errorf("initializing affinity match map: %w", err)
		}
		if option.Config.EnableIPv4 {
			if err := lbmap.Affinity4Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing affinity v4 map: %w", err)
			}
		}
		if option.Config.EnableIPv6 {
			if err := lbmap.Affinity6Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing affinity v6 map: %w", err)
			}
		}
	}

	if option.Config.EnableSVCSourceRangeCheck {
		if option.Config.EnableIPv4 {
			if err := lbmap.SourceRange4Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing source range v4 map: %w", err)
			}
		}
		if option.Config.EnableIPv6 {
			if err := lbmap.SourceRange6Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing source range v6 map: %w", err)
			}
		}
	}

	if option.Config.NodePortAlg == option.NodePortAlgMaglev {
		if err := lbmap.InitMaglevMaps(option.Config.EnableIPv4, option.Config.EnableIPv6, uint32(option.Config.MaglevTableSize)); err != nil {
			return fmt.Errorf("initializing maglev maps: %w", err)
		}
	}

	_, err := lbmap.NewSkipLBMap()
	if err != nil {
		return fmt.Errorf("initializing local redirect policy maps: %w", err)
	}

	return nil
}

func syncVTEP(context.Context) error {
	if option.Config.EnableVTEP {
		err := setupVTEPMapping()
		if err != nil {
			return err
		}
		err = setupRouteToVtepCidr()
		if err != nil {
			return err
		}
	}
	return nil
}

func setupVTEPMapping() error {
	for i, ep := range option.Config.VtepEndpoints {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: ep,
		}).Debug("Updating vtep map entry for VTEP")

		err := vtep.UpdateVTEPMapping(option.Config.VtepCIDRs[i], ep, option.Config.VtepMACs[i])
		if err != nil {
			return fmt.Errorf("Unable to set up VTEP ipcache mappings: %w", err)
		}
	}
	return nil
}

func setupRouteToVtepCidr() error {
	routeCidrs := []*cidr.CIDR{}

	filter := &netlink.Route{
		Table: linux_defaults.RouteTableVtep,
	}

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
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
	vtepMTU := mtu.EthernetMTU - mtu.TunnelOverhead

	if option.Config.EnableL7Proxy {
		for _, prefix := range addedVtepRoutes {
			ip4 := prefix.IP.To4()
			if ip4 == nil {
				return fmt.Errorf("Invalid VTEP CIDR IPv4 address: %v", ip4)
			}
			r := route.Route{
				Device: defaults.HostDevice,
				Prefix: *prefix.IPNet,
				Scope:  netlink.SCOPE_LINK,
				MTU:    vtepMTU,
				Table:  linux_defaults.RouteTableVtep,
			}
			if err := route.Upsert(r); err != nil {
				return fmt.Errorf("Update VTEP CIDR route error: %w", err)
			}
			log.WithFields(logrus.Fields{
				logfields.IPAddr: r.Prefix.String(),
			}).Info("VTEP route added")

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
		r := route.Route{
			Device: defaults.HostDevice,
			Prefix: *prefix.IPNet,
			Scope:  netlink.SCOPE_LINK,
			MTU:    vtepMTU,
			Table:  linux_defaults.RouteTableVtep,
		}
		if err := route.Delete(r); err != nil {
			return fmt.Errorf("Delete VTEP CIDR route error: %w", err)
		}
		log.WithFields(logrus.Fields{
			logfields.IPAddr: r.Prefix.String(),
		}).Info("VTEP route removed")

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

// Loader returns a reference to the loader implementation.
func (d *Daemon) Loader() datapath.Loader {
	return d.loader
}

// Orchestrator returns a reference to the orchestrator implementation.
func (d *Daemon) Orchestrator() datapath.Orchestrator {
	return d.orchestrator
}

// BandwidthManager returns a reference to the bandwidth manager implementation.
func (d *Daemon) BandwidthManager() datapath.BandwidthManager {
	return d.bwManager
}

func (d *Daemon) IPTablesManager() datapath.IptablesManager {
	return d.iptablesManager
}
