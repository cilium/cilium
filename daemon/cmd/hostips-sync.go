// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"iter"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/identity"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const syncHostIPsInterval = time.Minute

type syncHostIPsParams struct {
	cell.In

	Jobs          job.Registry
	Health        cell.Health
	DB            *statedb.DB
	Config        *option.DaemonConfig
	NodeAddresses statedb.Table[tables.NodeAddress]
	IPCache       *ipcache.IPCache
}

type syncHostIPs struct {
	params     syncHostIPsParams
	start      chan struct{}
	firstError chan error
}

func (s *syncHostIPs) StartAndWaitFirst(ctx context.Context) error {
	close(s.start)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-s.firstError:
		return err
	}
}

func newSyncHostIPs(lc cell.Lifecycle, p syncHostIPsParams) *syncHostIPs {
	s := &syncHostIPs{
		params:     p,
		start:      make(chan struct{}),
		firstError: make(chan error, 1),
	}

	if option.Config.DryMode {
		s.firstError <- nil
		return s
	}

	g := p.Jobs.NewGroup(p.Health)
	g.Add(job.OneShot("sync-hostips", s.loop))
	lc.Append(g)

	return s
}

func (s *syncHostIPs) loop(ctx context.Context, health cell.Health) error {
	// Wait for start signal. This is needed for now to synchronize with initialization
	// (e.g. IPcache restoration, map init) that still happens in newDaemon.
	select {
	case <-s.start:
	case <-ctx.Done():
		s.firstError <- ctx.Err()
		return nil
	}

	first := true
	ticker := time.NewTicker(syncHostIPsInterval)
	defer ticker.Stop()

	for {
		txn := s.params.DB.ReadTxn()
		addrs, watch := s.params.NodeAddresses.AllWatch(txn)

		err := s.sync(addrs)
		if err != nil {
			log.WithError(err).Errorf("Failed to sync host IPs, retrying later")
			health.Degraded("Failed to sync host IPs", err)
		} else {
			health.OK("Synchronized")
		}

		if first {
			first = false
			s.firstError <- err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		case <-ticker.C:
		}
	}
}

// sync adds local host entries to bpf lxcmap, as well as ipcache, if
// needed, and also notifies the daemon and network policy hosts cache if
// changes were made.
func (s *syncHostIPs) sync(addrs iter.Seq2[tables.NodeAddress, statedb.Revision]) error {
	type ipIDLabel struct {
		identity.IPIdentityPair
		labels.Labels
	}
	specialIdentities := make([]ipIDLabel, 0, 2)

	addIdentity := func(ip net.IP, mask net.IPMask, id identity.NumericIdentity, labels labels.Labels) {
		specialIdentities = append(specialIdentities, ipIDLabel{
			identity.IPIdentityPair{
				IP:   ip,
				Mask: mask,
				ID:   id,
			},
			labels,
		})
	}

	for addr := range addrs {
		if addr.DeviceName == tables.WildcardDeviceName {
			continue
		}
		ip := addr.Addr.AsSlice()
		if (!option.Config.EnableIPv4 && addr.Addr.Is4()) || (!option.Config.EnableIPv6 && addr.Addr.Is6()) {
			continue
		}
		if option.Config.IsExcludedLocalAddress(ip) {
			continue
		}
		addIdentity(ip, nil, identity.ReservedIdentityHost, labels.LabelHost)
	}

	if option.Config.EnableIPv6 {
		ipv6Ident := identity.ReservedIdentityWorldIPv6
		ipv6Label := labels.LabelWorldIPv6
		if !option.Config.EnableIPv4 {
			ipv6Ident = identity.ReservedIdentityWorld
			ipv6Label = labels.LabelWorld
		}
		addIdentity(net.IPv6zero, net.CIDRMask(0, net.IPv6len*8), ipv6Ident, ipv6Label)
	}

	if option.Config.EnableIPv4 {
		ipv4Ident := identity.ReservedIdentityWorldIPv4
		ipv4Label := labels.LabelWorldIPv4
		if !option.Config.EnableIPv6 {
			ipv4Ident = identity.ReservedIdentityWorld
			ipv4Label = labels.LabelWorld
		}
		addIdentity(net.IPv4zero, net.CIDRMask(0, net.IPv4len*8), ipv4Ident, ipv4Label)
	}

	existingEndpoints, err := lxcmap.DumpToMap()
	if err != nil {
		return fmt.Errorf("dump lxcmap: %w", err)
	}

	daemonResourceID := ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "reserved")
	for _, ipIDLblsPair := range specialIdentities {
		isHost := ipIDLblsPair.ID == identity.ReservedIdentityHost
		if isHost {
			added, err := lxcmap.SyncHostEntry(ipIDLblsPair.IP)
			if err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %w", err)
			}
			if added {
				log.WithField(logfields.IPAddr, ipIDLblsPair.IP).Debugf("Added local ip to endpoint map")
			}
		}

		delete(existingEndpoints, ipIDLblsPair.IP.String())

		lbls := ipIDLblsPair.Labels
		if ipIDLblsPair.ID.IsWorld() {
			p := netip.PrefixFrom(netipx.MustFromStdIP(ipIDLblsPair.IP), 0)
			s.params.IPCache.OverrideIdentity(p, lbls, source.Local, daemonResourceID)
		} else {
			s.params.IPCache.UpsertLabels(ippkg.IPToNetPrefix(ipIDLblsPair.IP),
				lbls,
				source.Local, daemonResourceID,
			)
		}
	}

	// existingEndpoints is a map from endpoint IP to endpoint info. Referring
	// to the key as host IP here because we only care about the host endpoint.
	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				return fmt.Errorf("unable to delete obsolete host IP: %w", err)
			} else {
				log.Debugf("Removed outdated host IP %s from endpoint map", hostIP)
			}
			s.params.IPCache.RemoveLabels(ippkg.IPToNetPrefix(ip), labels.LabelHost, daemonResourceID)
		}
	}

	// we have a reference to all ifindex values, so we update the related metric
	maxIfindex := uint32(0)
	for _, endpoint := range existingEndpoints {
		if endpoint.IfIndex > maxIfindex {
			maxIfindex = endpoint.IfIndex
		}
	}
	metrics.EndpointMaxIfindex.Set(float64(maxIfindex))

	return nil
}
