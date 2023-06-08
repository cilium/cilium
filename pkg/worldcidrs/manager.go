// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// worldcidrs is a simple controller for syncing CiliumWorldCIDRSets with their BPF map on the host.
// A CiliumWorldCIDRSet is a CRD that contains routing policy. This routing policy needs to be
// represented in to the datapath. The Manager is responsible for watching the api and updating the
// BPF map accordingly.
//
// Currently, a CiliumWorldCIDRSet may only request that a CIDR *not* be encapsulated. This is only
// useful in high-scale ipcache mode, where traffic is otherwise assumed to require encapsulation.
// As such, the manager (and its BPF map) are not not enabled unless high-scale mode is active.
package worldcidrs

import (
	"context"
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
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

	cell.ProvidePrivate(
		newWorldCIDRResource,
	),
)

// newWorldCIDRResource provides a store plus event stream that watches the
// cilium.io/v2alpha1/CiliumWorldCIDRSet api resource.
func newWorldCIDRResource(lc hive.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1.CiliumWorldCIDRSet] {
	if !dc.EnableHighScaleIPcache {
		return nil
	}

	if !c.IsEnabled() {
		return nil
	}

	return resource.New[*v2alpha1.CiliumWorldCIDRSet](
		lc, utils.ListerWatcherFromTyped[*v2alpha1.CiliumWorldCIDRSetList](
			c.CiliumV2alpha1().CiliumWorldCIDRSets(),
		))
}

// The world CIDRs manager stores the internal data tracking the world CIDRs.
// It also hooks up all the callbacks to update the BPF map accordingly.
type Manager struct {
	lock.Mutex
	wp *workerpool.WorkerPool

	cidrSetResource   resource.Resource[*v2alpha1.CiliumWorldCIDRSet]
	cidrGroupResource resource.Resource[*v2alpha1.CiliumCIDRGroup]

	// We won't care about most groups, so keep a list of ones about which we care.
	groupsInUse sets.Set[api.CIDRGroupRef]

	// CIDRsMap is the actualized BPF map to which we push changes
	CIDRsMap worldcidrsmap.Map
	// haveCidrs is the current state of the bpf map
	mapState sets.Set[netip.Prefix]

	controllers *controller.Manager
}

type Params struct {
	cell.In

	CIDRSetResource   resource.Resource[*v2alpha1.CiliumWorldCIDRSet]
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
		cidrSetResource:   p.CIDRSetResource,
		cidrGroupResource: p.CIDRGroupResource,
		CIDRsMap:          p.CIDRsMap,

		groupsInUse: sets.Set[api.CIDRGroupRef]{},
		mapState:    sets.Set[netip.Prefix]{},

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

	// Perform initial synchronization of the the k8s Store to the bpf map
	if err := m.sync(startCtx); err != nil {
		err = fmt.Errorf("failed to perform initial sync of CiliumWorldCIDRSet: %w", err)
		log.WithError(err).Error("Failed to start WorldCIDR manager")
	}

	log.Infof("synced %d items in to the WorldCIDR map", len(m.mapState))

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
	cidrSets := m.cidrSetResource.Events(ctx)
	cidrGroups := m.cidrGroupResource.Events(ctx)
	for cidrSets != nil && cidrGroups != nil {
		select {
		case ev, ok := <-cidrSets:
			if !ok {
				cidrSets = nil
				continue
			}
			logger := log.WithFields(logrus.Fields{
				logfields.CiliumWorldCIDRSetName: ev.Key.Name,
				logfields.Event:                  ev.Kind,
			})
			logger.Debug("Processing CiliumWorldCIDRSet event")

			switch ev.Kind {
			case resource.Sync:
				// nothing to do, we manually synced earlier
			case resource.Upsert, resource.Delete:
				m.triggerSync()
			}
			ev.Done(nil)
		case ev, ok := <-cidrGroups:
			if !ok {
				cidrGroups = nil
				continue
			}

			switch ev.Kind {
			case resource.Sync:
				// nothing to do, we manually synced earlier
			case resource.Upsert, resource.Delete:
				m.cidrGroupUpdated(ev.Key.Name)
			}
			ev.Done(nil)
		}
	}
	return nil
}

func (m *Manager) cidrGroupUpdated(name string) {
	m.Lock()
	defer m.Unlock()
	if m.groupsInUse.Has(api.CIDRGroupRef(name)) {
		log.WithField(logfields.CIDRGroupRef, name).Debug("Processing CiliumCIDRGroup event")
		m.triggerSync()
	}
}

// loadMapState loads the bpf map in to our copy.
// It is currently only called once on startup.
func (m *Manager) loadMapState() error {
	mapState := make(sets.Set[netip.Prefix], len(m.mapState))
	err := m.CIDRsMap.IterateWithCallback(
		func(key netip.Prefix) {
			mapState.Insert(key)
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
	setStore, err := m.cidrSetResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve CiliumWorldCIDRSet store: %w", err)
	}

	groupStore, err := m.cidrGroupResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve CiliumCIDRGroup store: %w", err)
	}

	// determine desired cidrs and groups
	wantPrefixes, groupsInUse := m.loadAllCIDRs(setStore, groupStore)
	m.groupsInUse = groupsInUse

	return m.apply(wantPrefixes)
}

// apply pushes any chages down from the desired set of CIDRS in to the map
func (m *Manager) apply(wantPrefixes sets.Set[netip.Prefix]) error {
	toAdd := wantPrefixes.Difference(m.mapState)
	toRemove := m.mapState.Difference(wantPrefixes)

	if len(toAdd) == 0 && len(toRemove) == 0 {
		return nil
	}

	log.WithFields(logrus.Fields{
		"added":   toAdd.UnsortedList(),
		"removed": toRemove.UnsortedList(),
	}).Debugf("Pushing changes in to BPF map %s", worldcidrsmap.MapName4)

	// The order of the next 2 function calls matters, as by first adding
	// missing CIDRs and only then removing obsolete ones we make sure there
	// will be no connectivity disruption.
	add := toAdd.UnsortedList()
	rem := toRemove.UnsortedList()
	if err := m.CIDRsMap.Add(add...); err != nil {
		return fmt.Errorf("failed to insert %d entries from bpf map %s: %w", len(toAdd), worldcidrsmap.MapName4, err)
	}
	m.mapState.Insert(add...)

	if err := m.CIDRsMap.Delete(toRemove.UnsortedList()...); err != nil {
		return fmt.Errorf("failed to delete %d entries from bpf map %s: %w", len(toRemove), worldcidrsmap.MapName4, err)
	}
	m.mapState.Delete(rem...)

	return nil
}
