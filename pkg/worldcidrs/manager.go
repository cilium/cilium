// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// worldcidrs is a simple controller for syncing encapsulation configuration from the apiserver
// to the world cirs map. It is only relevant for high-scale ipcache clusters.
//
// The world cidrs bpf map is used by high-scale ipcache clusters to determine whether or not a given
// address should be encapsulated (because the ipcache doesn't contain this information). It is
// configured by the end user setting special labels on a CiliumCIDRGRoup object. If the object\
// has the label "network.cilium.io/high-scale-encap=<true|false>", all CIDRs in that group are inserted
// accordingly.
package worldcidrs

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "world-cidr-manager")
)

const controllerName = "world-cidr-manager"

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"worldcidrs",
	"World CIDRs allow defining routing policy on a per-CIDR basis",
	cell.Provide(NewWorldCIDRsManager),
	cell.Invoke(func(*Manager) {}),
)

// The world CIDRs manager stores the internal data tracking the world CIDRs.
// It also hooks up all the callbacks to update the BPF map accordingly.
type Manager struct {
	lock.Mutex
	wp *workerpool.WorkerPool

	cidrGroupResource resource.Resource[*v2alpha1.CiliumCIDRGroup]

	// CIDRsMap is the actualized BPF map to which we push changes
	CIDRsMap worldcidrsmap.Map

	// mapState is the current value of the bpf map
	mapState map[netip.Prefix]bool

	controllers *controller.Manager
}

type Params struct {
	cell.In

	CIDRGroupResource resource.Resource[*v2alpha1.CiliumCIDRGroup]
	DaemonConfig      *option.DaemonConfig
	CIDRsMap          worldcidrsmap.Map

	Lifecycle hive.Lifecycle
}

// NewWorldCIDRsManager returns a new world CIDRs manager.
func NewWorldCIDRsManager(p Params) *Manager {
	if !p.DaemonConfig.EnableHighScaleIPcache {
		return nil
	}

	manager := &Manager{
		cidrGroupResource: p.CIDRGroupResource,
		CIDRsMap:          p.CIDRsMap,

		mapState: map[netip.Prefix]bool{},

		controllers: controller.NewManager(),
	}

	p.Lifecycle.Append(manager)

	return manager
}

// Start performs the initial synchronization and sets up event handlers.
func (m *Manager) Start(startCtx hive.HookContext) error {
	if m == nil {
		return nil
	}
	// Create or load the map
	if err := m.CIDRsMap.Load(true); err != nil {
		return err
	}

	// load state from map
	if err := m.loadMapState(); err != nil {
		return fmt.Errorf("failed to load initial map state: %w", err)
	}

	// This will trigger the initial synchronization
	m.controllers.UpdateController(
		controllerName,
		controller.ControllerParams{
			DoFunc: m.sync,
		},
	)

	// Start processing any changes
	m.wp = workerpool.New(1)
	m.wp.Submit("processEvents", m.processEvents)
	return nil
}

func (m *Manager) Stop(startCtx hive.HookContext) error {
	if m == nil {
		return nil
	}
	m.wp.Close()
	m.controllers.RemoveAllAndWait()
	return nil
}

func (m *Manager) triggerSync() {
	m.controllers.TriggerController(controllerName)
}

func (m *Manager) processEvents(ctx context.Context) error {
	for ev := range m.cidrGroupResource.Events(ctx) {
		switch ev.Kind {
		case resource.Sync:
			// nothing to do, we manually synced earlier
		case resource.Upsert, resource.Delete:
			m.triggerSync()
		}
		ev.Done(nil)
	}
	return nil
}

// loadMapState loads the bpf map in to our copy.
// It is currently only called once on startup.
func (m *Manager) loadMapState() error {
	mapState := make(map[netip.Prefix]bool, len(m.mapState))
	err := m.CIDRsMap.IterateWithCallback(
		func(key netip.Prefix, val bool) {
			mapState[key] = val
		})
	if err != nil {
		return err
	}

	m.mapState = mapState
	return nil
}

// sync is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (world CIDR map entries).
//
// Whenever it encounters a recoverable error, it will just log it and move to the next
// item, in order to sync as many states as possible.
func (m *Manager) sync(ctx context.Context) error {
	m.Lock()
	defer m.Unlock()

	// this will block until the informer's initial list is done
	groupStore, err := m.cidrGroupResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve CiliumCIDRGroup store: %w", err)
	}

	// determine desired cidrs and groups
	wantConfig := m.loadAllCIDRs(groupStore)

	err = m.apply(wantConfig)
	if err != nil {
		log.WithError(err).Warn("Failed to apply changes to the world cidrs map")
	}
	return err
}

// apply pushes any chages down from the desired set of CIDRS in to the map
func (m *Manager) apply(wantConfig map[netip.Prefix]bool) error {
	if m.mapState == nil {
		if err := m.loadMapState(); err != nil {
			return fmt.Errorf("failed to load current map state: %w", err)
		}
	}

	updates := map[netip.Prefix]bool{}
	deletes := sets.Set[netip.Prefix]{}

	for cidr, encap := range wantConfig {
		haveEncap, exists := m.mapState[cidr]
		if !exists || haveEncap != encap {
			updates[cidr] = encap
		}
	}

	for cidr := range m.mapState {
		if _, exists := wantConfig[cidr]; !exists {
			deletes.Insert(cidr)
		}
	}

	log.WithFields(logrus.Fields{
		"updates": updates,
		"deletes": deletes.UnsortedList(),
	}).Debugf("Pushing changes in to BPF map %s", worldcidrsmap.MapName4)

	if err := m.CIDRsMap.Add(updates); err != nil {
		// mapstate is unclear; remove it for later re-scan
		m.mapState = nil
		return fmt.Errorf("failed to update in to bpf map %s: %w", worldcidrsmap.MapName4, err)
	}

	if err := m.CIDRsMap.Delete(deletes.UnsortedList()...); err != nil {
		m.mapState = nil
		return fmt.Errorf("failed to delete entries from bpf map %s: %w", worldcidrsmap.MapName4, err)
	}

	m.mapState = wantConfig
	return nil
}
