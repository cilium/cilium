// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"

	"github.com/cilium/cilium/operator/pkg/networkpolicy/external-groups/provider"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// The ExternalGroupManager watches for external groups referenced in policies
// (i.e. ToGroups / FromGroups) and synchronizes them to CiliumCIDRGroups.
// At present, it can reference AWS VPCs when a cluster is deployed in AWS.
//
// Because external Groups entities within policies are not named, we need
// to create an artificial key. We hash the JSON representation of the group
// and use this as label key.
//
// For example, this ToGroups:
//
//	  spec:
//		   ingress:
//		   - fromGroups:
//		     - aws:
//		       labels:
//		         foo: bar
//
// may result in this CCG:
//
//	  apiVersion: cilium.io/v2
//	  kind: CiliumCIDRGroup
//	  metadata:
//	 	annotations:
//		      cilium.io/group: '{"aws":{"labels":{"foo":"bar"}}}'
//		labels:
//		    app.kubernetes.io/part-of: cilium
//		    cilium.io/policy-group: ""
//		    extgrp.cilium.io/eyJhd3MiOnsibGFiZWxzIjp7ImZvbyI6ImJhciJ9fX3RSgKMKjoryUdhArsogjT: ""
//	  spec:
//		   externalCIDRs:
//		   - 1.1.1.1/32
type ExternalGroupManager interface {
	SetResourceGroups(gk schema.GroupKind, namespace, name string, groups []*api.Groups)

	// RegisterResource tells the group manager about a resource that may provide external groups.
	//
	// It will not delete potentially-stale groups until all resources are marked as synced.
	RegisterResourceKind(gk schema.GroupKind)

	// ResourceSynced tells the group manager that all groups for a given kind have been
	// provided, and that it may be safe to GC stale groups.
	ResourceKindSynced(gk schema.GroupKind)
}

type ExternalGroupManagerParams struct {
	cell.In

	Log *slog.Logger

	DB      *statedb.DB
	EGTable statedb.RWTable[*ExternalGroup]

	Clientset   client.Clientset
	CCGResource resource.Resource[*cilium_v2.CiliumCIDRGroup]
	JG          job.Group
}

func NewGroupManager(params ExternalGroupManagerParams) ExternalGroupManager {
	// If there are no group providers, ignore
	if !provider.Enabled() {
		return &noopGroupManager{}
	}
	gm := newGroupManager(params)
	gm.RegisterResourceKind(gkCCG)

	// reflect CCGs in to the DB
	params.JG.Add(job.Observer(
		"policy-external-group-ccg-watcher",
		gm.handleCCGEvent,
		params.CCGResource,
	))

	return gm
}

func newGroupManager(params ExternalGroupManagerParams) *externalGroupManager {
	gc := &externalGroupManager{
		log: params.Log,

		db:  params.DB,
		tbl: params.EGTable,

		clientset:   params.Clientset,
		ccgResource: params.CCGResource,

		pendingResources: sets.Set[schema.GroupKind]{},
		ready:            make(chan struct{}),

		trig: make(chan struct{}, 1),

		emptyResources: make(sets.Set[Owner]),
	}

	return gc
}

type externalGroupManager struct {
	log *slog.Logger

	db  *statedb.DB
	tbl statedb.RWTable[*ExternalGroup]

	clientset   client.Clientset
	ccgResource resource.Resource[*cilium_v2.CiliumCIDRGroup]

	// trig is a len-1 channel sent when manual
	// synchronization is desired
	trig chan struct{}

	pendingLock lock.Mutex
	// pendingResources blocks initial synchronization until all "upstream" resources
	// have been synchronized.
	pendingResources sets.Set[schema.GroupKind]
	// ready is closed when all upstream resources have synced
	ready chan struct{}

	// cache of known-empty resources,
	// so we can cheaply skip the common case of resources with zero groups.
	emptyResourcesLock lock.Mutex
	emptyResources     sets.Set[Owner]
}

// SetResourceGroups informs the controller of the external groups that belong
// to a given resource.
//
// An empty list of groups indicates the resource no longer requires groups.
func (gm *externalGroupManager) SetResourceGroups(gk schema.GroupKind, namespace, name string, groups []*api.Groups) {
	owner := Owner{
		Group:     gk.Group,
		Kind:      gk.Kind,
		Namespace: namespace,
		Name:      name,
	}

	if gm.canSkip(owner, (len(groups) == 0)) {
		return
	}

	wtxn := gm.db.WriteTxn(gm.tbl)
	defer wtxn.Abort()

	changed := false

	// Add owner to all groups
	keep := make(sets.Set[string], len(groups))
	for _, group := range groups {
		row, upd := gm.addToGroup(wtxn, owner, group)
		keep.Insert(row.ID)
		changed = changed || upd
	}

	// Remove owner from all stale groups
	upd := gm.pruneOwner(wtxn, owner, keep)
	changed = changed || upd

	if !changed {
		return
	}

	gm.log.Info("Policy External Groups changed for resource",
		logfields.Group, gk.Group,
		logfields.Kind, gk.Kind,
		logfields.K8sNamespace, namespace,
		logfields.Name, name,
		logfields.Count, len(groups),
	)

	// Commit and trigger the sync loop
	wtxn.Commit()
	gm.trigger()
}

// canSkip checks to see if this owner went from 0 groups to 0 groups.
// In that case, we can skip the entire rigamarole.
// This also updates the empty cache.
func (gm *externalGroupManager) canSkip(owner Owner, isEmpty bool) bool {
	gm.emptyResourcesLock.Lock()
	defer gm.emptyResourcesLock.Unlock()

	wasEmpty := gm.emptyResources.Has(owner)

	if wasEmpty && isEmpty {
		return true
	}

	if isEmpty {
		gm.emptyResources.Insert(owner)
	} else {
		gm.emptyResources.Delete(owner)
	}
	return false
}

// addToGroup creates this group if necessary, and records the owner as referencing it.
// returns true if any changes were made
func (gm *externalGroupManager) addToGroup(wtxn statedb.WriteTxn, owner Owner, group *api.Groups) (*ExternalGroup, bool) {
	id := group.Hash()
	row, _, found := gm.tbl.Get(wtxn, egIDIndex.Query(id))
	new := false
	if found {
		row = row.ShallowCopy()
	} else {
		new = true
		row = &ExternalGroup{
			ID:       id,
			ExtGroup: group,
			Owners:   part.Set[Owner]{},
			// NextRefresh should be zero so we force refresh
		}
	}

	// If this ExternalGroup already has this owner, there's nothing to do.
	if row.Owners.Has(owner) {
		return row, false
	}

	// Add this owner to the set of Owners and insert to this wtxn
	row.Owners = row.Owners.Set(owner)

	// This may be a stub row created by a CCG -- set the group
	row.ExtGroup = group

	_, _, err := gm.tbl.Insert(wtxn, row)
	if err != nil {
		// unreachable
		gm.log.Error("BUG: Upsert in to "+ExternalGroupTableName+" failed",
			logfields.Error, err)
	}
	if new {
		gm.log.Info("inserted new ExternalGroup",
			logfields.Group, id,
		)
	}
	return row, true
}

// pruneOwner removes this owner from all groups except those in keep
// returns true if any changes were made
func (gm *externalGroupManager) pruneOwner(wtxn statedb.WriteTxn, owner Owner, keep sets.Set[string]) bool {
	changed := false

	rows := gm.tbl.List(wtxn, ownerIndex.Query(owner))
	for row := range rows {
		if keep.Has(row.ID) {
			continue
		}

		row = row.ShallowCopy()
		row.Owners = row.Owners.Delete(owner)
		// Even if Owners is empty, we still keep the row;
		// the sync operation will clean it up.
		_, _, err := gm.tbl.Insert(wtxn, row)
		if err != nil {
			// unreachable
			gm.log.Error("BUG: delete from "+ExternalGroupTableName+" failed",
				logfields.Error, err)
		}
		changed = true
	}
	return changed
}

func (gm *externalGroupManager) RegisterResourceKind(gk schema.GroupKind) {
	gm.pendingLock.Lock()
	defer gm.pendingLock.Unlock()

	gm.pendingResources.Insert(gk)
}

func (gm *externalGroupManager) ResourceKindSynced(gk schema.GroupKind) {
	gm.pendingLock.Lock()
	defer gm.pendingLock.Unlock()

	if !gm.pendingResources.Has(gk) {
		gm.log.Warn("BUG: Resource marked as synced twice!",
			logfields.Resource, gk)
		return
	}

	gm.pendingResources.Delete(gk)
	if gm.pendingResources.Len() == 0 {
		close(gm.ready)
	}
}

// trigger forces the group-to-ccg loop to synchronize
func (gm *externalGroupManager) trigger() {
	select {
	case gm.trig <- struct{}{}:
	default:
	}
}

// noopGroupManager is returned when groups are not enabled (i.e. not on AWS)
type noopGroupManager struct{}

func (ng *noopGroupManager) SetResourceGroups(gk schema.GroupKind, namespace, name string, groups []*api.Groups) {
}
func (ng *noopGroupManager) RegisterResourceKind(gk schema.GroupKind) {}
func (ng *noopGroupManager) ResourceKindSynced(gk schema.GroupKind)   {}
