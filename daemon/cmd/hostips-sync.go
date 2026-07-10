// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const syncHostIPsInterval = time.Minute

var hostIPSyncCell = cell.Module(
	"hostip-sync",
	"Syncs local host entries to the endpoints BPF map and IPCache",

	cell.Provide(newSyncHostIPs),
)

type syncHostIPsParams struct {
	cell.In

	Logger        *slog.Logger
	JobGroup      job.Group
	DB            *statedb.DB
	Config        *option.DaemonConfig
	NodeAddresses statedb.Table[tables.NodeAddress]
	IPCache       *ipcache.IPCache
	LXCMap        lxcmap.Map
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

func newSyncHostIPs(p syncHostIPsParams) *syncHostIPs {
	s := &syncHostIPs{
		params:     p,
		start:      make(chan struct{}),
		firstError: make(chan error, 1),
	}

	if option.Config.DryMode {
		s.firstError <- nil
		return s
	}

	p.JobGroup.Add(job.OneShot("sync-hostips", s.loop))

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
			s.params.Logger.Error("Failed to sync host IPs, retrying later", logfields.Error, err)
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
		IP     netip.Addr
		ID     identity.NumericIdentity
		Labels labels.Labels
	}
	specialIdentities := make([]ipIDLabel, 0, 2)

	addIdentity := func(ip netip.Addr, id identity.NumericIdentity, labels labels.Labels) {
		specialIdentities = append(specialIdentities, ipIDLabel{
			IP:     ip,
			ID:     id,
			Labels: labels,
		})
	}

	for addr := range addrs {
		if addr.DeviceName == tables.WildcardDeviceName {
			continue
		}
		if (!option.Config.EnableIPv4 && addr.Addr.Is4()) || (!option.Config.EnableIPv6 && addr.Addr.Is6()) {
			continue
		}
		if option.Config.IsExcludedLocalAddress(addr.Addr) {
			continue
		}
		addIdentity(addr.Addr, identity.ReservedIdentityHost, labels.LabelHost)
	}

	if option.Config.EnableIPv6 {
		ipv6Ident := identity.ReservedIdentityWorldIPv6
		ipv6Label := labels.LabelWorldIPv6
		if !option.Config.EnableIPv4 {
			ipv6Ident = identity.ReservedIdentityWorld
			ipv6Label = labels.LabelWorld
		}
		addIdentity(netip.IPv6Unspecified(), ipv6Ident, ipv6Label)
	}

	if option.Config.EnableIPv4 {
		ipv4Ident := identity.ReservedIdentityWorldIPv4
		ipv4Label := labels.LabelWorldIPv4
		if !option.Config.EnableIPv6 {
			ipv4Ident = identity.ReservedIdentityWorld
			ipv4Label = labels.LabelWorld
		}
		addIdentity(netip.IPv4Unspecified(), ipv4Ident, ipv4Label)
	}

	existingEndpoints, err := s.params.LXCMap.DumpToMap()
	if err != nil {
		return fmt.Errorf("dump lxcmap: %w", err)
	}

	daemonResourceID := ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "reserved")
	for _, ipIDLblsPair := range specialIdentities {
		isHost := ipIDLblsPair.ID == identity.ReservedIdentityHost
		if isHost {
			added, err := s.params.LXCMap.SyncHostEntry(ipIDLblsPair.IP)
			if err != nil {
				return fmt.Errorf("unable to add host entry to endpoint map: %w", err)
			}
			if added {
				s.params.Logger.Debug(
					"Added local ip to endpoint map",
					logfields.IPAddr, ipIDLblsPair.IP,
				)
			}
		}

		delete(existingEndpoints, ipIDLblsPair.IP)

		lbls := ipIDLblsPair.Labels
		if ipIDLblsPair.ID.IsWorld() {
			p := cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(ipIDLblsPair.IP, 0))
			s.params.IPCache.OverrideIdentity(p, lbls, source.Local, daemonResourceID)
		} else {
			p := cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(ipIDLblsPair.IP, ipIDLblsPair.IP.BitLen()))
			s.params.IPCache.UpsertMetadata(p, source.Local, daemonResourceID, lbls)
		}
	}

	// existingEndpoints is a map from endpoint IP to endpoint info. Referring
	// to the key as host IP here because we only care about the host endpoint.
	for addr, info := range existingEndpoints {
		if addr.IsValid() && info.IsHost() {
			if err := s.params.LXCMap.DeleteEntry(addr); err != nil {
				return fmt.Errorf("unable to delete obsolete host IP: %w", err)
			} else {
				s.params.Logger.Debug(
					"Removed outdated host IP from endpoint map",
					logfields.IPAddr, addr,
				)
			}
			p := cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, addr.BitLen()))
			s.params.IPCache.RemoveMetadata(p, daemonResourceID, labels.LabelHost)
		}
	}

	return nil
}
