/*
Copyright 2018 The Kubernetes Authors.

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

package handler

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ EventHandler = &enqueueRequestForOwner{}

var log = logf.RuntimeLog.WithName("eventhandler").WithName("enqueueRequestForOwner")

// OwnerOption modifies an EnqueueRequestForOwner EventHandler.
type OwnerOption func(e *enqueueRequestForOwner)

// EnqueueRequestForOwner enqueues Requests for the Owners of an object.  E.g. the object that created
// the object that was the source of the Event.
//
// If a ReplicaSet creates Pods, users may reconcile the ReplicaSet in response to Pod Events using:
//
// - a source.Kind Source with Type of Pod.
//
// - a handler.enqueueRequestForOwner EventHandler with an OwnerType of ReplicaSet and OnlyControllerOwner set to true.
func EnqueueRequestForOwner(scheme *runtime.Scheme, mapper meta.RESTMapper, ownerType client.Object, opts ...OwnerOption) EventHandler {
	e := &enqueueRequestForOwner{
		ownerType: ownerType,
		mapper:    mapper,
	}
	if err := e.parseOwnerTypeGroupKind(scheme); err != nil {
		panic(err)
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// OnlyControllerOwner if provided will only look at the first OwnerReference with Controller: true.
func OnlyControllerOwner() OwnerOption {
	return func(e *enqueueRequestForOwner) {
		e.isController = true
	}
}

type enqueueRequestForOwner struct {
	// ownerType is the type of the Owner object to look for in OwnerReferences.  Only Group and Kind are compared.
	ownerType runtime.Object

	// isController if set will only look at the first OwnerReference with Controller: true.
	isController bool

	// groupKind is the cached Group and Kind from OwnerType
	groupKind schema.GroupKind

	// mapper maps GroupVersionKinds to Resources
	mapper meta.RESTMapper
}

// Create implements EventHandler.
func (e *enqueueRequestForOwner) Create(ctx context.Context, evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.getOwnerReconcileRequest(evt.Object, reqs)
	for req := range reqs {
		q.Add(req)
	}
}

// Update implements EventHandler.
func (e *enqueueRequestForOwner) Update(ctx context.Context, evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.getOwnerReconcileRequest(evt.ObjectOld, reqs)
	e.getOwnerReconcileRequest(evt.ObjectNew, reqs)
	for req := range reqs {
		q.Add(req)
	}
}

// Delete implements EventHandler.
func (e *enqueueRequestForOwner) Delete(ctx context.Context, evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.getOwnerReconcileRequest(evt.Object, reqs)
	for req := range reqs {
		q.Add(req)
	}
}

// Generic implements EventHandler.
func (e *enqueueRequestForOwner) Generic(ctx context.Context, evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.getOwnerReconcileRequest(evt.Object, reqs)
	for req := range reqs {
		q.Add(req)
	}
}

// parseOwnerTypeGroupKind parses the OwnerType into a Group and Kind and caches the result.  Returns false
// if the OwnerType could not be parsed using the scheme.
func (e *enqueueRequestForOwner) parseOwnerTypeGroupKind(scheme *runtime.Scheme) error {
	// Get the kinds of the type
	kinds, _, err := scheme.ObjectKinds(e.ownerType)
	if err != nil {
		log.Error(err, "Could not get ObjectKinds for OwnerType", "owner type", fmt.Sprintf("%T", e.ownerType))
		return err
	}
	// Expect only 1 kind.  If there is more than one kind this is probably an edge case such as ListOptions.
	if len(kinds) != 1 {
		err := fmt.Errorf("expected exactly 1 kind for OwnerType %T, but found %s kinds", e.ownerType, kinds)
		log.Error(nil, "expected exactly 1 kind for OwnerType", "owner type", fmt.Sprintf("%T", e.ownerType), "kinds", kinds)
		return err
	}
	// Cache the Group and Kind for the OwnerType
	e.groupKind = schema.GroupKind{Group: kinds[0].Group, Kind: kinds[0].Kind}
	return nil
}

// getOwnerReconcileRequest looks at object and builds a map of reconcile.Request to reconcile
// owners of object that match e.OwnerType.
func (e *enqueueRequestForOwner) getOwnerReconcileRequest(object metav1.Object, result map[reconcile.Request]empty) {
	// Iterate through the OwnerReferences looking for a match on Group and Kind against what was requested
	// by the user
	for _, ref := range e.getOwnersReferences(object) {
		// Parse the Group out of the OwnerReference to compare it to what was parsed out of the requested OwnerType
		refGV, err := schema.ParseGroupVersion(ref.APIVersion)
		if err != nil {
			log.Error(err, "Could not parse OwnerReference APIVersion",
				"api version", ref.APIVersion)
			return
		}

		// Compare the OwnerReference Group and Kind against the OwnerType Group and Kind specified by the user.
		// If the two match, create a Request for the objected referred to by
		// the OwnerReference.  Use the Name from the OwnerReference and the Namespace from the
		// object in the event.
		if ref.Kind == e.groupKind.Kind && refGV.Group == e.groupKind.Group {
			// Match found - add a Request for the object referred to in the OwnerReference
			request := reconcile.Request{NamespacedName: types.NamespacedName{
				Name: ref.Name,
			}}

			// if owner is not namespaced then we should not set the namespace
			mapping, err := e.mapper.RESTMapping(e.groupKind, refGV.Version)
			if err != nil {
				log.Error(err, "Could not retrieve rest mapping", "kind", e.groupKind)
				return
			}
			if mapping.Scope.Name() != meta.RESTScopeNameRoot {
				request.Namespace = object.GetNamespace()
			}

			result[request] = empty{}
		}
	}
}

// getOwnersReferences returns the OwnerReferences for an object as specified by the enqueueRequestForOwner
// - if IsController is true: only take the Controller OwnerReference (if found)
// - if IsController is false: take all OwnerReferences.
func (e *enqueueRequestForOwner) getOwnersReferences(object metav1.Object) []metav1.OwnerReference {
	if object == nil {
		return nil
	}

	// If not filtered as Controller only, then use all the OwnerReferences
	if !e.isController {
		return object.GetOwnerReferences()
	}
	// If filtered to a Controller, only take the Controller OwnerReference
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		return []metav1.OwnerReference{*ownerRef}
	}
	// No Controller OwnerReference found
	return nil
}
