// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/groups/provider"
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
//		generateName: extgroup-to-cidrgroup-
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

const (
	// How often, approximately, to re-synchronize groups
	ResyncInterval = 10 * time.Minute
)

type ExternalGroupManagerParams struct {
	cell.In

	Log         *slog.Logger
	Clientset   client.Clientset
	JobGroup    job.Group
	CCGResource resource.Resource[*cilium_v2.CiliumCIDRGroup]
}

func NewGroupManager(params ExternalGroupManagerParams) ExternalGroupManager {
	// If there are no group providers, ignore
	if !provider.Enabled() {
		return &noopGroupManager{}
	}

	gc := &externalGroupController{
		log:         params.Log,
		clientset:   params.Clientset,
		ccgResource: params.CCGResource,

		pendingResources: sets.Set[schema.GroupKind]{},
		ready:            make(chan struct{}),
		triggerSync:      job.NewTrigger(),

		groups:      map[groupKey]*api.Groups{},
		groupOwners: map[groupKey]sets.Set[owner]{},
		owners:      sets.Set[owner]{},
		toUpdate:    sets.Set[groupKey]{},
		nextRefresh: map[groupKey]time.Time{},
	}

	params.JobGroup.Add(job.Timer(
		"sync-external-groups-to-ccg",
		gc.sync,
		time.Minute,
		job.WithTrigger(gc.triggerSync),
	))

	return gc
}

type owner struct {
	gk        schema.GroupKind
	namespace string
	name      string
}

type groupKey string

type externalGroupController struct {
	log         *slog.Logger
	clientset   client.Clientset
	ccgResource resource.Resource[*cilium_v2.CiliumCIDRGroup]
	triggerSync job.Trigger

	pendingLock lock.Mutex
	// pendingResources blocks initial synchronization until all "upstream" resources
	// have been synchronized.
	pendingResources sets.Set[schema.GroupKind]

	// ready is closed when all upstream resources have synced
	ready chan struct{}

	// lock controls access to groups / groupOwners / owners / toUpdate
	lock lock.Mutex

	// Groups is the set of all known group configurations. The key is the hash of the json representation of the group
	groups map[groupKey]*api.Groups

	// groupOwners is the set of owning resources for a given group.
	groupOwners map[groupKey]sets.Set[owner]

	// owners is the set of known owners; used for skipping unnecessary updates.
	owners sets.Set[owner]

	// toUpdate is a set of groups that have changed. It is consumed by a controller
	toUpdate sets.Set[groupKey]

	// existing is a map from groupKey to an existing CCG
	// no lock, as the sync loop is single-threaded.
	// nil if we haven't loaded from the apiserver yet
	existing map[groupKey]*cilium_v2.CiliumCIDRGroup

	// nextRefresh is the deadline for refresh for each group
	//
	// We should resynchronize every group approximately every 5 minutes.
	//
	// Rather than maintaining a controller for each group, we keep a
	// soft deadline for every known group. The synchronize loop will run
	// every few minutes or so.
	nextRefresh map[groupKey]time.Time
}

// SetResourceGroups informs the controller of the external groups that belong
// to a given resource.
//
// An empty list of groups indicates the resource no longer requires groups.
func (gc *externalGroupController) SetResourceGroups(gk schema.GroupKind, namespace, name string, groups []*api.Groups) {
	gc.lock.Lock()
	defer gc.lock.Unlock()

	own := owner{
		gk:        gk,
		namespace: namespace,
		name:      name,
	}

	// Shortcut: the resource never had any groups, and still doesn't.
	if len(groups) == 0 && !gc.owners.Has(own) {
		return
	}

	incoming := make(map[groupKey]*api.Groups, len(groups))
	for _, g := range groups {
		incoming[groupKey(g.Hash())] = g
	}

	// Scan new groups, adding all new ones and setting owners
	for key, g := range incoming {
		if _, exists := gc.groups[key]; !exists {
			gc.groups[key] = g
			gc.groupOwners[key] = sets.Set[owner]{}

			gc.log.Info("New group, scheduling for reconciliation",
				logfields.Group, key)

			// Flag this group as needing reconciliation
			gc.toUpdate.Insert(key)
		}

		gc.groupOwners[key].Insert(own)
	}

	// scan existing owner references, cleaning out any stale ones
	for key := range gc.groupOwners {
		// resource references this group
		if _, keep := incoming[key]; keep {
			continue
		}

		// if last owner reference, schedule deletion of group
		gc.groupOwners[key].Delete(own)
		if gc.groupOwners[key].Len() == 0 {
			delete(gc.groups, key)
			delete(gc.groupOwners, key)
			gc.toUpdate.Insert(key)
			gc.log.Info("Group now has zero owners, scheduling for deletion",
				logfields.Group, key)
		}
	}

	// track set of known resources.
	if len(groups) > 0 {
		gc.owners.Insert(own)
	} else {
		gc.owners.Delete(own)
	}

	if len(gc.toUpdate) > 0 {
		gc.triggerSync.Trigger()
	}
}

func (gc *externalGroupController) RegisterResourceKind(gk schema.GroupKind) {
	gc.pendingLock.Lock()
	defer gc.pendingLock.Unlock()

	gc.pendingResources.Insert(gk)
}

func (gc *externalGroupController) ResourceKindSynced(gk schema.GroupKind) {
	gc.pendingLock.Lock()
	defer gc.pendingLock.Unlock()

	if !gc.pendingResources.Has(gk) {
		gc.log.Warn("BUG: Resource marked as synced twice!",
			logfields.Resource, gk)
		return
	}

	gc.pendingResources.Delete(gk)
	if gc.pendingResources.Len() == 0 {
		close(gc.ready)
	}
}

// noopGroupManager is returned when groups are not enabled (i.e. not on AWS)
type noopGroupManager struct{}

func (ng *noopGroupManager) SetResourceGroups(gk schema.GroupKind, namespace, name string, groups []*api.Groups) {
}
func (ng *noopGroupManager) RegisterResourceKind(gk schema.GroupKind) {}
func (ng *noopGroupManager) ResourceKindSynced(gk schema.GroupKind)   {}
