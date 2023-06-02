// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	datapathIpcache "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// LocalConfig returns the local configuration of the daemon's nodediscovery.
func (d *Daemon) LocalConfig() *datapath.LocalNodeConfiguration {
	d.nodeDiscovery.WaitForLocalNodeInit()
	return &d.nodeDiscovery.LocalConfig
}

func deleteHostDevice() {
	link, err := netlink.LinkByName(defaults.HostDevice)
	if err != nil {
		log.WithError(err).Warningf("Unable to lookup host device %s. No old cilium_host interface exists", defaults.HostDevice)
		return
	}

	if err := netlink.LinkDel(link); err != nil {
		log.WithError(err).Errorf("Unable to delete host device %s to change allocation CIDR", defaults.HostDevice)
	}
}

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
		return fmt.Errorf("unable to retrieve host network interfaces: %s", err)
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

// SetPrefilter sets the preftiler for the given daemon.
func (d *Daemon) SetPrefilter(preFilter datapath.PreFilter) {
	d.preFilter = preFilter
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

// syncHostIPs adds local host entries to bpf lxcmap, as well as ipcache, if
// needed, and also notifies the daemon and network policy hosts cache if
// changes were made.
func (d *Daemon) syncHostIPs() error {
	if option.Config.DryMode {
		return nil
	}

	specialIdentities := []identity.IPIdentityPair{}

	if option.Config.EnableIPv4 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv4().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv4 addresses")
		}

		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					})
			}
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, net.IPv4len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	if option.Config.EnableIPv6 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv6().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv6 addresses")
		}

		addrs = append(addrs, node.GetIPv6Router())
		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					})
			}
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, net.IPv6len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	existingEndpoints, err := lxcmap.DumpToMap()
	if err != nil {
		return err
	}

	for _, ipIDPair := range specialIdentities {
		isHost := ipIDPair.ID == identity.ReservedIdentityHost
		if isHost {
			added, err := lxcmap.SyncHostEntry(ipIDPair.IP)
			if err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %s", err)
			}
			if added {
				log.WithField(logfields.IPAddr, ipIDPair.IP).Debugf("Added local ip to endpoint map")
			}
		}

		delete(existingEndpoints, ipIDPair.IP.String())

		// Upsert will not propagate (reserved:foo->ID) mappings across the cluster,
		// and we specifically don't want to do so.
		//
		// This upsert will fail with ErrOverwrite continuously as long as the
		// EP / CN watcher have found an apiserver IP and upserted it into the
		// ipcache. Until then, it is expected to succeed.
		d.ipcache.Upsert(ipIDPair.PrefixString(), nil, 0, nil, ipcache.Identity{
			ID:     ipIDPair.ID,
			Source: d.sourceByIP(ipIDPair.IP, source.Local),
		})
	}

	// existingEndpoints is a map from endpoint IP to endpoint info. Referring
	// to the key as host IP here because we only care about the host endpoint.
	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr: hostIP,
				}).Warn("Unable to delete obsolete host IP from BPF map")
			} else {
				log.Debugf("Removed outdated host IP %s from endpoint map", hostIP)
			}

			d.ipcache.Delete(hostIP, d.sourceByIP(ip, source.Local))
		}
	}

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

func (d *Daemon) sourceByIP(ip net.IP, defaultSrc source.Source) source.Source {
	if addr, ok := ippkg.AddrFromIP(ip); ok {
		lbls := d.ipcache.GetMetadataLabelsByIP(addr)
		if lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]) {
			return source.KubeAPIServer
		}
	} else {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: ip,
		}).Warning("BUG: Invalid addr detected in host stack. Please report this bug to the Cilium developers.")
	}
	return defaultSrc
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

	if option.Config.TunnelingEnabled() {
		if err := tunnel.TunnelMap().Recreate(); err != nil {
			return fmt.Errorf("initializing tunnel map: %w", err)
		}
	}

	if option.Config.EnableSRv6 {
		srv6map.CreateMaps()
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

	if err := policymap.InitCallMaps(option.Config.EnableEnvoyConfig); err != nil {
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

	// Set up the list of IPCache listeners in the daemon, to be
	// used by syncEndpointsAndHostIPs()
	// xDS cache will be added later by calling AddListener(), but only if necessary.
	d.ipcache.SetListeners([]ipcache.IPIdentityMappingListener{
		datapathIpcache.NewListener(d, d, d.ipcache),
	})

	if option.Config.EnableIPv4 && option.Config.EnableIPMasqAgent {
		if err := ipmasq.IPMasq4Map().OpenOrCreate(); err != nil {
			return fmt.Errorf("initializing masquerading map: %w", err)
		}
	}

	// Start the controller for periodic sync of the metrics map with
	// the prometheus server.
	controller.NewManager().UpdateController("metricsmap-bpf-prom-sync",
		controller.ControllerParams{
			DoFunc:      metricsmap.SyncMetricsMap,
			RunInterval: 5 * time.Second,
			Context:     d.ctx,
		})

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

	return nil
}

func setupIPSec() (int, uint8, error) {
	if !option.Config.EncryptNode {
		ipsec.DeleteIPsecEncryptRoute()
	}

	if !option.Config.EnableIPSec {
		return 0, 0, nil
	}

	authKeySize, spi, err := ipsec.LoadIPSecKeysFile(option.Config.IPSecKeyFile)
	if err != nil {
		return 0, 0, err
	}
	node.SetIPsecKeyIdentity(spi)
	return authKeySize, spi, nil
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

// Datapath returns a reference to the datapath implementation.
func (d *Daemon) Datapath() datapath.Datapath {
	return d.datapath
}
