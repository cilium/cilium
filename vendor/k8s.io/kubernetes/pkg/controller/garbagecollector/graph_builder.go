/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package garbagecollector

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/golang/glog"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type eventType int

func (e eventType) String() string {
	switch e {
	case addEvent:
		return "add"
	case updateEvent:
		return "update"
	case deleteEvent:
		return "delete"
	default:
		return fmt.Sprintf("unknown(%d)", int(e))
	}
}

const (
	addEvent eventType = iota
	updateEvent
	deleteEvent
)

type event struct {
	eventType eventType
	obj       interface{}
	// the update event comes with an old object, but it's not used by the garbage collector.
	oldObj interface{}
	gvk    schema.GroupVersionKind
}

// GraphBuilder: based on the events supplied by the informers, GraphBuilder updates
// uidToNode, a graph that caches the dependencies as we know, and enqueues
// items to the attemptToDelete and attemptToOrphan.
type GraphBuilder struct {
	restMapper meta.RESTMapper

	// each monitor list/watches a resource, the results are funneled to the
	// dependencyGraphBuilder
	monitors    monitors
	monitorLock sync.Mutex
	// informersStarted is closed after after all of the controllers have been initialized and are running.
	// After that it is safe to start them here, before that it is not.
	informersStarted <-chan struct{}

	// stopCh drives shutdown. If it is nil, it indicates that Run() has not been
	// called yet. If it is non-nil, then when closed it indicates everything
	// should shut down.
	//
	// This channel is also protected by monitorLock.
	stopCh <-chan struct{}

	// metaOnlyClientPool uses a special codec, which removes fields except for
	// apiVersion, kind, and metadata during decoding.
	metaOnlyClientPool dynamic.ClientPool
	// used to register exactly once the rate limiters of the clients used by
	// the `monitors`.
	registeredRateLimiterForControllers *RegisteredRateLimiter
	// monitors are the producer of the graphChanges queue, graphBuilder alters
	// the in-memory graph according to the changes.
	graphChanges workqueue.RateLimitingInterface
	// uidToNode doesn't require a lock to protect, because only the
	// single-threaded GraphBuilder.processGraphChanges() reads/writes it.
	uidToNode *concurrentUIDToNode
	// GraphBuilder is the producer of attemptToDelete and attemptToOrphan, GC is the consumer.
	attemptToDelete workqueue.RateLimitingInterface
	attemptToOrphan workqueue.RateLimitingInterface
	// GraphBuilder and GC share the absentOwnerCache. Objects that are known to
	// be non-existent are added to the cached.
	absentOwnerCache *UIDCache
	sharedInformers  informers.SharedInformerFactory
	ignoredResources map[schema.GroupResource]struct{}
}

// monitor runs a Controller with a local stop channel.
type monitor struct {
	controller cache.Controller

	// stopCh stops Controller. If stopCh is nil, the monitor is considered to be
	// not yet started.
	stopCh chan struct{}
}

// Run is intended to be called in a goroutine. Multiple calls of this is an
// error.
func (m *monitor) Run() {
	m.controller.Run(m.stopCh)
}

type monitors map[schema.GroupVersionResource]*monitor

func listWatcher(client dynamic.Interface, resource schema.GroupVersionResource) *cache.ListWatch {
	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			// APIResource.Kind is not used by the dynamic client, so
			// leave it empty. We want to list this resource in all
			// namespaces if it's namespace scoped, so leave
			// APIResource.Namespaced as false is all right.
			apiResource := metav1.APIResource{Name: resource.Resource}
			return client.ParameterCodec(dynamic.VersionedParameterEncoderWithV1Fallback).
				Resource(&apiResource, metav1.NamespaceAll).
				List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			// APIResource.Kind is not used by the dynamic client, so
			// leave it empty. We want to list this resource in all
			// namespaces if it's namespace scoped, so leave
			// APIResource.Namespaced as false is all right.
			apiResource := metav1.APIResource{Name: resource.Resource}
			return client.ParameterCodec(dynamic.VersionedParameterEncoderWithV1Fallback).
				Resource(&apiResource, metav1.NamespaceAll).
				Watch(options)
		},
	}
}

func (gb *GraphBuilder) controllerFor(resource schema.GroupVersionResource, kind schema.GroupVersionKind) (cache.Controller, error) {
	handlers := cache.ResourceEventHandlerFuncs{
		// add the event to the dependencyGraphBuilder's graphChanges.
		AddFunc: func(obj interface{}) {
			event := &event{
				eventType: addEvent,
				obj:       obj,
				gvk:       kind,
			}
			gb.graphChanges.Add(event)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// TODO: check if there are differences in the ownerRefs,
			// finalizers, and DeletionTimestamp; if not, ignore the update.
			event := &event{
				eventType: updateEvent,
				obj:       newObj,
				oldObj:    oldObj,
				gvk:       kind,
			}
			gb.graphChanges.Add(event)
		},
		DeleteFunc: func(obj interface{}) {
			// delta fifo may wrap the object in a cache.DeletedFinalStateUnknown, unwrap it
			if deletedFinalStateUnknown, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = deletedFinalStateUnknown.Obj
			}
			event := &event{
				eventType: deleteEvent,
				obj:       obj,
				gvk:       kind,
			}
			gb.graphChanges.Add(event)
		},
	}
	shared, err := gb.sharedInformers.ForResource(resource)
	if err == nil {
		glog.V(4).Infof("using a shared informer for resource %q, kind %q", resource.String(), kind.String())
		// need to clone because it's from a shared cache
		shared.Informer().AddEventHandlerWithResyncPeriod(handlers, ResourceResyncTime)
		return shared.Informer().GetController(), nil
	} else {
		glog.V(4).Infof("unable to use a shared informer for resource %q, kind %q: %v", resource.String(), kind.String(), err)
	}

	// TODO: consider store in one storage.
	glog.V(5).Infof("create storage for resource %s", resource)
	client, err := gb.metaOnlyClientPool.ClientForGroupVersionKind(kind)
	if err != nil {
		return nil, err
	}
	// TODO: since the gv is never unregistered, isn't this a memory leak?
	gb.registeredRateLimiterForControllers.registerIfNotPresent(resource.GroupVersion(), client, "garbage_collector_monitoring")
	_, monitor := cache.NewInformer(
		listWatcher(client, resource),
		nil,
		ResourceResyncTime,
		// don't need to clone because it's not from shared cache
		handlers,
	)
	return monitor, nil
}

// syncMonitors rebuilds the monitor set according to the supplied resources,
// creating or deleting monitors as necessary. It will return any error
// encountered, but will make an attempt to create a monitor for each resource
// instead of immediately exiting on an error. It may be called before or after
// Run. Monitors are NOT started as part of the sync. To ensure all existing
// monitors are started, call startMonitors.
func (gb *GraphBuilder) syncMonitors(resources map[schema.GroupVersionResource]struct{}) error {
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()

	toRemove := gb.monitors
	if toRemove == nil {
		toRemove = monitors{}
	}
	current := monitors{}
	errs := []error{}
	kept := 0
	added := 0
	for resource := range resources {
		if _, ok := ignoredResources[resource.GroupResource()]; ok {
			continue
		}
		if m, ok := toRemove[resource]; ok {
			current[resource] = m
			delete(toRemove, resource)
			kept++
			continue
		}
		kind, err := gb.restMapper.KindFor(resource)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't look up resource %q: %v", resource, err))
			continue
		}
		c, err := gb.controllerFor(resource, kind)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't start monitor for resource %q: %v", resource, err))
			continue
		}
		current[resource] = &monitor{controller: c}
		added++
	}
	gb.monitors = current

	for _, monitor := range toRemove {
		if monitor.stopCh != nil {
			close(monitor.stopCh)
		}
	}

	glog.V(4).Infof("synced monitors; added %d, kept %d, removed %d", added, kept, len(toRemove))
	// NewAggregate returns nil if errs is 0-length
	return utilerrors.NewAggregate(errs)
}

// startMonitors ensures the current set of monitors are running. Any newly
// started monitors will also cause shared informers to be started.
//
// If called before Run, startMonitors does nothing (as there is no stop channel
// to support monitor/informer execution).
func (gb *GraphBuilder) startMonitors() {
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()

	if gb.stopCh == nil {
		return
	}

	// we're waiting until after the informer start that happens once all the controllers are initialized.  This ensures
	// that they don't get unexpected events on their work queues.
	<-gb.informersStarted

	monitors := gb.monitors
	started := 0
	for _, monitor := range monitors {
		if monitor.stopCh == nil {
			monitor.stopCh = make(chan struct{})
			gb.sharedInformers.Start(gb.stopCh)
			go monitor.Run()
			started++
		}
	}
	glog.V(4).Infof("started %d new monitors, %d currently running", started, len(monitors))
}

// IsSynced returns true if any monitors exist AND all those monitors'
// controllers HasSynced functions return true. This means IsSynced could return
// true at one time, and then later return false if all monitors were
// reconstructed.
func (gb *GraphBuilder) IsSynced() bool {
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()

	if len(gb.monitors) == 0 {
		return false
	}

	for _, monitor := range gb.monitors {
		if !monitor.controller.HasSynced() {
			return false
		}
	}
	return true
}

// Run sets the stop channel and starts monitor execution until stopCh is
// closed. Any running monitors will be stopped before Run returns.
func (gb *GraphBuilder) Run(stopCh <-chan struct{}) {
	glog.Infof("GraphBuilder running")
	defer glog.Infof("GraphBuilder stopping")

	// Set up the stop channel.
	gb.monitorLock.Lock()
	gb.stopCh = stopCh
	gb.monitorLock.Unlock()

	// Start monitors and begin change processing until the stop channel is
	// closed.
	gb.startMonitors()
	wait.Until(gb.runProcessGraphChanges, 1*time.Second, stopCh)

	// Stop any running monitors.
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()
	monitors := gb.monitors
	stopped := 0
	for _, monitor := range monitors {
		if monitor.stopCh != nil {
			stopped++
			close(monitor.stopCh)
		}
	}
	glog.Infof("stopped %d of %d monitors", stopped, len(monitors))
}

var ignoredResources = map[schema.GroupResource]struct{}{
	{Group: "extensions", Resource: "replicationcontrollers"}:              {},
	{Group: "", Resource: "bindings"}:                                      {},
	{Group: "", Resource: "componentstatuses"}:                             {},
	{Group: "", Resource: "events"}:                                        {},
	{Group: "authentication.k8s.io", Resource: "tokenreviews"}:             {},
	{Group: "authorization.k8s.io", Resource: "subjectaccessreviews"}:      {},
	{Group: "authorization.k8s.io", Resource: "selfsubjectaccessreviews"}:  {},
	{Group: "authorization.k8s.io", Resource: "localsubjectaccessreviews"}: {},
	{Group: "authorization.k8s.io", Resource: "selfsubjectrulesreviews"}:   {},
	{Group: "apiregistration.k8s.io", Resource: "apiservices"}:             {},
	{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}: {},
}

// DefaultIgnoredResources returns the default set of resources that the garbage collector controller
// should ignore. This is exposed so downstream integrators can have access to the defaults, and add
// to them as necessary when constructing the controller.
func DefaultIgnoredResources() map[schema.GroupResource]struct{} {
	return ignoredResources
}

func (gb *GraphBuilder) enqueueChanges(e *event) {
	gb.graphChanges.Add(e)
}

// addDependentToOwners adds n to owners' dependents list. If the owner does not
// exist in the gb.uidToNode yet, a "virtual" node will be created to represent
// the owner. The "virtual" node will be enqueued to the attemptToDelete, so that
// attemptToDeleteItem() will verify if the owner exists according to the API server.
func (gb *GraphBuilder) addDependentToOwners(n *node, owners []metav1.OwnerReference) {
	for _, owner := range owners {
		ownerNode, ok := gb.uidToNode.Read(owner.UID)
		if !ok {
			// Create a "virtual" node in the graph for the owner if it doesn't
			// exist in the graph yet. Then enqueue the virtual node into the
			// attemptToDelete. The garbage processor will enqueue a virtual delete
			// event to delete it from the graph if API server confirms this
			// owner doesn't exist.
			ownerNode = &node{
				identity: objectReference{
					OwnerReference: owner,
					Namespace:      n.identity.Namespace,
				},
				dependents: make(map[*node]struct{}),
			}
			glog.V(5).Infof("add virtual node.identity: %s\n\n", ownerNode.identity)
			gb.uidToNode.Write(ownerNode)
			gb.attemptToDelete.Add(ownerNode)
		}
		ownerNode.addDependent(n)
	}
}

// insertNode insert the node to gb.uidToNode; then it finds all owners as listed
// in n.owners, and adds the node to their dependents list.
func (gb *GraphBuilder) insertNode(n *node) {
	gb.uidToNode.Write(n)
	gb.addDependentToOwners(n, n.owners)
}

// removeDependentFromOwners remove n from owners' dependents list.
func (gb *GraphBuilder) removeDependentFromOwners(n *node, owners []metav1.OwnerReference) {
	for _, owner := range owners {
		ownerNode, ok := gb.uidToNode.Read(owner.UID)
		if !ok {
			continue
		}
		ownerNode.deleteDependent(n)
	}
}

// removeNode removes the node from gb.uidToNode, then finds all
// owners as listed in n.owners, and removes n from their dependents list.
func (gb *GraphBuilder) removeNode(n *node) {
	gb.uidToNode.Delete(n.identity.UID)
	gb.removeDependentFromOwners(n, n.owners)
}

type ownerRefPair struct {
	oldRef metav1.OwnerReference
	newRef metav1.OwnerReference
}

// TODO: profile this function to see if a naive N^2 algorithm performs better
// when the number of references is small.
func referencesDiffs(old []metav1.OwnerReference, new []metav1.OwnerReference) (added []metav1.OwnerReference, removed []metav1.OwnerReference, changed []ownerRefPair) {
	oldUIDToRef := make(map[string]metav1.OwnerReference)
	for _, value := range old {
		oldUIDToRef[string(value.UID)] = value
	}
	oldUIDSet := sets.StringKeySet(oldUIDToRef)
	newUIDToRef := make(map[string]metav1.OwnerReference)
	for _, value := range new {
		newUIDToRef[string(value.UID)] = value
	}
	newUIDSet := sets.StringKeySet(newUIDToRef)

	addedUID := newUIDSet.Difference(oldUIDSet)
	removedUID := oldUIDSet.Difference(newUIDSet)
	intersection := oldUIDSet.Intersection(newUIDSet)

	for uid := range addedUID {
		added = append(added, newUIDToRef[uid])
	}
	for uid := range removedUID {
		removed = append(removed, oldUIDToRef[uid])
	}
	for uid := range intersection {
		if !reflect.DeepEqual(oldUIDToRef[uid], newUIDToRef[uid]) {
			changed = append(changed, ownerRefPair{oldRef: oldUIDToRef[uid], newRef: newUIDToRef[uid]})
		}
	}
	return added, removed, changed
}

// returns if the object in the event just transitions to "being deleted".
func deletionStarts(oldObj interface{}, newAccessor metav1.Object) bool {
	// The delta_fifo may combine the creation and update of the object into one
	// event, so if there is no oldObj, we just return if the newObj (via
	// newAccessor) is being deleted.
	if oldObj == nil {
		if newAccessor.GetDeletionTimestamp() == nil {
			return false
		}
		return true
	}
	oldAccessor, err := meta.Accessor(oldObj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("cannot access oldObj: %v", err))
		return false
	}
	return beingDeleted(newAccessor) && !beingDeleted(oldAccessor)
}

func beingDeleted(accessor metav1.Object) bool {
	return accessor.GetDeletionTimestamp() != nil
}

func hasDeleteDependentsFinalizer(accessor metav1.Object) bool {
	finalizers := accessor.GetFinalizers()
	for _, finalizer := range finalizers {
		if finalizer == metav1.FinalizerDeleteDependents {
			return true
		}
	}
	return false
}

func hasOrphanFinalizer(accessor metav1.Object) bool {
	finalizers := accessor.GetFinalizers()
	for _, finalizer := range finalizers {
		if finalizer == metav1.FinalizerOrphanDependents {
			return true
		}
	}
	return false
}

// this function takes newAccessor directly because the caller already
// instantiates an accessor for the newObj.
func startsWaitingForDependentsDeleted(oldObj interface{}, newAccessor metav1.Object) bool {
	return deletionStarts(oldObj, newAccessor) && hasDeleteDependentsFinalizer(newAccessor)
}

// this function takes newAccessor directly because the caller already
// instantiates an accessor for the newObj.
func startsWaitingForDependentsOrphaned(oldObj interface{}, newAccessor metav1.Object) bool {
	return deletionStarts(oldObj, newAccessor) && hasOrphanFinalizer(newAccessor)
}

// if an blocking ownerReference points to an object gets removed, or gets set to
// "BlockOwnerDeletion=false", add the object to the attemptToDelete queue.
func (gb *GraphBuilder) addUnblockedOwnersToDeleteQueue(removed []metav1.OwnerReference, changed []ownerRefPair) {
	for _, ref := range removed {
		if ref.BlockOwnerDeletion != nil && *ref.BlockOwnerDeletion {
			node, found := gb.uidToNode.Read(ref.UID)
			if !found {
				glog.V(5).Infof("cannot find %s in uidToNode", ref.UID)
				continue
			}
			gb.attemptToDelete.Add(node)
		}
	}
	for _, c := range changed {
		wasBlocked := c.oldRef.BlockOwnerDeletion != nil && *c.oldRef.BlockOwnerDeletion
		isUnblocked := c.newRef.BlockOwnerDeletion == nil || (c.newRef.BlockOwnerDeletion != nil && !*c.newRef.BlockOwnerDeletion)
		if wasBlocked && isUnblocked {
			node, found := gb.uidToNode.Read(c.newRef.UID)
			if !found {
				glog.V(5).Infof("cannot find %s in uidToNode", c.newRef.UID)
				continue
			}
			gb.attemptToDelete.Add(node)
		}
	}
}

func (gb *GraphBuilder) processTransitions(oldObj interface{}, newAccessor metav1.Object, n *node) {
	if startsWaitingForDependentsOrphaned(oldObj, newAccessor) {
		glog.V(5).Infof("add %s to the attemptToOrphan", n.identity)
		gb.attemptToOrphan.Add(n)
		return
	}
	if startsWaitingForDependentsDeleted(oldObj, newAccessor) {
		glog.V(2).Infof("add %s to the attemptToDelete, because it's waiting for its dependents to be deleted", n.identity)
		// if the n is added as a "virtual" node, its deletingDependents field is not properly set, so always set it here.
		n.markDeletingDependents()
		for dep := range n.dependents {
			gb.attemptToDelete.Add(dep)
		}
		gb.attemptToDelete.Add(n)
	}
}

func (gb *GraphBuilder) runProcessGraphChanges() {
	for gb.processGraphChanges() {
	}
}

// Dequeueing an event from graphChanges, updating graph, populating dirty_queue.
func (gb *GraphBuilder) processGraphChanges() bool {
	item, quit := gb.graphChanges.Get()
	if quit {
		return false
	}
	defer gb.graphChanges.Done(item)
	event, ok := item.(*event)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expect a *event, got %v", item))
		return true
	}
	obj := event.obj
	accessor, err := meta.Accessor(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("cannot access obj: %v", err))
		return true
	}
	glog.V(5).Infof("GraphBuilder process object: %s/%s, namespace %s, name %s, uid %s, event type %v", event.gvk.GroupVersion().String(), event.gvk.Kind, accessor.GetNamespace(), accessor.GetName(), string(accessor.GetUID()), event.eventType)
	// Check if the node already exsits
	existingNode, found := gb.uidToNode.Read(accessor.GetUID())
	switch {
	case (event.eventType == addEvent || event.eventType == updateEvent) && !found:
		newNode := &node{
			identity: objectReference{
				OwnerReference: metav1.OwnerReference{
					APIVersion: event.gvk.GroupVersion().String(),
					Kind:       event.gvk.Kind,
					UID:        accessor.GetUID(),
					Name:       accessor.GetName(),
				},
				Namespace: accessor.GetNamespace(),
			},
			dependents:         make(map[*node]struct{}),
			owners:             accessor.GetOwnerReferences(),
			deletingDependents: beingDeleted(accessor) && hasDeleteDependentsFinalizer(accessor),
			beingDeleted:       beingDeleted(accessor),
		}
		gb.insertNode(newNode)
		// the underlying delta_fifo may combine a creation and a deletion into
		// one event, so we need to further process the event.
		gb.processTransitions(event.oldObj, accessor, newNode)
	case (event.eventType == addEvent || event.eventType == updateEvent) && found:
		// handle changes in ownerReferences
		added, removed, changed := referencesDiffs(existingNode.owners, accessor.GetOwnerReferences())
		if len(added) != 0 || len(removed) != 0 || len(changed) != 0 {
			// check if the changed dependency graph unblock owners that are
			// waiting for the deletion of their dependents.
			gb.addUnblockedOwnersToDeleteQueue(removed, changed)
			// update the node itself
			existingNode.owners = accessor.GetOwnerReferences()
			// Add the node to its new owners' dependent lists.
			gb.addDependentToOwners(existingNode, added)
			// remove the node from the dependent list of node that are no longer in
			// the node's owners list.
			gb.removeDependentFromOwners(existingNode, removed)
		}

		if beingDeleted(accessor) {
			existingNode.markBeingDeleted()
		}
		gb.processTransitions(event.oldObj, accessor, existingNode)
	case event.eventType == deleteEvent:
		if !found {
			glog.V(5).Infof("%v doesn't exist in the graph, this shouldn't happen", accessor.GetUID())
			return true
		}
		// removeNode updates the graph
		gb.removeNode(existingNode)
		existingNode.dependentsLock.RLock()
		defer existingNode.dependentsLock.RUnlock()
		if len(existingNode.dependents) > 0 {
			gb.absentOwnerCache.Add(accessor.GetUID())
		}
		for dep := range existingNode.dependents {
			gb.attemptToDelete.Add(dep)
		}
		for _, owner := range existingNode.owners {
			ownerNode, found := gb.uidToNode.Read(owner.UID)
			if !found || !ownerNode.isDeletingDependents() {
				continue
			}
			// this is to let attempToDeleteItem check if all the owner's
			// dependents are deleted, if so, the owner will be deleted.
			gb.attemptToDelete.Add(ownerNode)
		}
	}
	return true
}
