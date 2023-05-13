// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrs

import (
	"context"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "worldcidrs")
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"worldcidrs",
	"World CIDRs allow defining IPs that are outside of the Cilium domain",
	cell.Provide(NewWorldCIDRsManager),
)

// CIDRSetID includes CIDR set name and namespace.
type CIDRSetID = types.NamespacedName

// CIDRSet is the internal representation of CiliumWorldCIDRSets.
type CIDRSet struct {
	// id is the parsed config name and namespace
	id CIDRSetID

	cidrs []*net.IPNet
}

// The world CIDRs manager stores the internal data tracking the world CIDRs.
// It also hooks up all the callbacks to update the BPF map accordingly.
type Manager struct {
	lock.Mutex

	// cacheStatus is used to check if the agent has synced its
	// cache with the k8s API server
	cacheStatus k8s.CacheStatus

	// cidrSets stores CIDR sets indexed by their ID
	cidrSets map[CIDRSetID]*CIDRSet
}

type Params struct {
	cell.In

	CacheStatus  k8s.CacheStatus
	DaemonConfig *option.DaemonConfig

	Lifecycle hive.Lifecycle
}

// NewWorldCIDRsManager returns a new world CIDRs manager.
func NewWorldCIDRsManager(p Params) *Manager {
	if !p.DaemonConfig.EnableHighScaleIPcache {
		return nil
	}

	manager := &Manager{
		cacheStatus: p.CacheStatus,
		cidrSets:    make(map[CIDRSetID]*CIDRSet),
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			manager.runReconciliationAfterK8sSync(ctx)
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			cancel()
			return nil
		},
	})

	return manager
}

// runReconciliationAfterK8sSync spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) runReconciliationAfterK8sSync(ctx context.Context) {
	go func() {
		select {
		case <-manager.cacheStatus:
			manager.Lock()
			manager.reconcile()
			manager.Unlock()
		case <-ctx.Done():
		}
	}()
}

// Event handlers

// OnAddWorldCIDRSet parses the given CIDR set and updates internal state
// with the CIDRs.
func (manager *Manager) OnAddWorldCIDRSet(cidrSet CIDRSet) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumWorldCIDRSetName, cidrSet.id.Name)

	if _, ok := manager.cidrSets[cidrSet.id]; !ok {
		logger.Info("Added CiliumWorldCIDRSet")
	} else {
		logger.Info("Updated CiliumWorldCIDRSet")
	}

	manager.cidrSets[cidrSet.id] = &cidrSet

	manager.reconcile()
}

// OnDeleteWorldCIDRSet deletes the internal state associated with the given
// world CIDR set, including BPF map entries.
func (manager *Manager) OnDeleteWorldCIDRSet(id CIDRSetID) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumWorldCIDRSetName, id.Name)

	if manager.cidrSets[id] == nil {
		logger.Warn("Can't delete CiliumWorldCIDRSet: set not found")
		return
	}

	delete(manager.cidrSets, id)
	logger.Info("Deleted CiliumWorldCIDRSet")

	manager.reconcile()
}

func (manager *Manager) addMissingCIDRs() {
	worldCIDRs := map[worldcidrsmap.WorldCIDRKey4]worldcidrsmap.WorldCIDRVal{}
	worldcidrsmap.WorldCIDRsMap.IterateWithCallback(
		func(key *worldcidrsmap.WorldCIDRKey4, val *worldcidrsmap.WorldCIDRVal) {
			worldCIDRs[*key] = *val
		})

	addCIDR := func(cidr *net.IPNet) {
		worldCIDRKey := worldcidrsmap.NewWorldCIDRKey4(cidr)
		_, cidrPresent := worldCIDRs[worldCIDRKey]

		if cidrPresent {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.CIDR: cidr,
		})

		if err := worldcidrsmap.WorldCIDRsMap.Add(cidr); err != nil {
			logger.WithError(err).Error("Error adding world CIDR")
		} else {
			logger.Info("World CIDR added")
		}
	}

	for _, cidrSet := range manager.cidrSets {
		for _, cidr := range cidrSet.cidrs {
			addCIDR(cidr)
		}
	}
}

// removeUnusedCIDRs is responsible for removing any entry in the world CIDR
// BPF map which is not baked by an actual k8s CiliumWorldCIDRSet.
func (manager *Manager) removeUnusedCIDRs() {
	worldCIDRs := map[worldcidrsmap.WorldCIDRKey4]worldcidrsmap.WorldCIDRVal{}
	worldcidrsmap.WorldCIDRsMap.IterateWithCallback(
		func(key *worldcidrsmap.WorldCIDRKey4, val *worldcidrsmap.WorldCIDRVal) {
			worldCIDRs[*key] = *val
		})

nextCIDR:
	for worldCIDR := range worldCIDRs {
		for _, cidrSet := range manager.cidrSets {
			for _, cidr := range cidrSet.cidrs {
				if worldCIDR.Matches(cidr) {
					continue nextCIDR
				}
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.CIDR: worldCIDR.GetCIDR(),
		})

		if err := worldcidrsmap.WorldCIDRsMap.Delete(worldCIDR.GetCIDR()); err != nil {
			logger.WithError(err).Error("Error removing world CIDR")
		} else {
			logger.Info("World CIDR removed")
		}
	}
}

// reconcile is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (world CIDR map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcile() {
	if !manager.cacheStatus.Synchronized() {
		return
	}

	// The order of the next 2 function calls matters, as by first adding
	// missing CIDRs and only then removing obsolete ones we make sure there
	// will be no connectivity disruption.
	manager.addMissingCIDRs()
	manager.removeUnusedCIDRs()
}
