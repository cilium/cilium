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

package predicate

import (
	"maps"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"
)

var log = logf.RuntimeLog.WithName("predicate").WithName("eventFilters")

// Predicate filters events before enqueuing the keys.
type Predicate = TypedPredicate[client.Object]

// TypedPredicate filters events before enqueuing the keys.
type TypedPredicate[T any] interface {
	// Create returns true if the Create event should be processed
	Create(event.TypedCreateEvent[T]) bool

	// Delete returns true if the Delete event should be processed
	Delete(event.TypedDeleteEvent[T]) bool

	// Update returns true if the Update event should be processed
	Update(event.TypedUpdateEvent[T]) bool

	// Generic returns true if the Generic event should be processed
	Generic(event.TypedGenericEvent[T]) bool
}

var _ Predicate = Funcs{}
var _ Predicate = ResourceVersionChangedPredicate{}
var _ Predicate = GenerationChangedPredicate{}
var _ Predicate = AnnotationChangedPredicate{}
var _ Predicate = or[client.Object]{}
var _ Predicate = and[client.Object]{}
var _ Predicate = not[client.Object]{}

// Funcs is a function that implements Predicate.
type Funcs = TypedFuncs[client.Object]

// TypedFuncs is a function that implements TypedPredicate.
type TypedFuncs[T any] struct {
	// Create returns true if the Create event should be processed
	CreateFunc func(event.TypedCreateEvent[T]) bool

	// Delete returns true if the Delete event should be processed
	DeleteFunc func(event.TypedDeleteEvent[T]) bool

	// Update returns true if the Update event should be processed
	UpdateFunc func(event.TypedUpdateEvent[T]) bool

	// Generic returns true if the Generic event should be processed
	GenericFunc func(event.TypedGenericEvent[T]) bool
}

// Create implements Predicate.
func (p TypedFuncs[T]) Create(e event.TypedCreateEvent[T]) bool {
	if p.CreateFunc != nil {
		return p.CreateFunc(e)
	}
	return true
}

// Delete implements Predicate.
func (p TypedFuncs[T]) Delete(e event.TypedDeleteEvent[T]) bool {
	if p.DeleteFunc != nil {
		return p.DeleteFunc(e)
	}
	return true
}

// Update implements Predicate.
func (p TypedFuncs[T]) Update(e event.TypedUpdateEvent[T]) bool {
	if p.UpdateFunc != nil {
		return p.UpdateFunc(e)
	}
	return true
}

// Generic implements Predicate.
func (p TypedFuncs[T]) Generic(e event.TypedGenericEvent[T]) bool {
	if p.GenericFunc != nil {
		return p.GenericFunc(e)
	}
	return true
}

// NewPredicateFuncs returns a predicate funcs that applies the given filter function
// on CREATE, UPDATE, DELETE and GENERIC events. For UPDATE events, the filter is applied
// to the new object.
func NewPredicateFuncs(filter func(object client.Object) bool) Funcs {
	return Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return filter(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return filter(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return filter(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return filter(e.Object)
		},
	}
}

// NewTypedPredicateFuncs returns a predicate funcs that applies the given filter function
// on CREATE, UPDATE, DELETE and GENERIC events. For UPDATE events, the filter is applied
// to the new object.
func NewTypedPredicateFuncs[T any](filter func(object T) bool) TypedFuncs[T] {
	return TypedFuncs[T]{
		CreateFunc: func(e event.TypedCreateEvent[T]) bool {
			return filter(e.Object)
		},
		UpdateFunc: func(e event.TypedUpdateEvent[T]) bool {
			return filter(e.ObjectNew)
		},
		DeleteFunc: func(e event.TypedDeleteEvent[T]) bool {
			return filter(e.Object)
		},
		GenericFunc: func(e event.TypedGenericEvent[T]) bool {
			return filter(e.Object)
		},
	}
}

// ResourceVersionChangedPredicate implements a default update predicate function on resource version change.
type ResourceVersionChangedPredicate struct {
	Funcs
}

// Update implements default UpdateEvent filter for validating resource version change.
func (ResourceVersionChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil {
		log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if e.ObjectNew == nil {
		log.Error(nil, "Update event has no new object to update", "event", e)
		return false
	}

	return e.ObjectNew.GetResourceVersion() != e.ObjectOld.GetResourceVersion()
}

// GenerationChangedPredicate implements a default update predicate function on Generation change.
//
// This predicate will skip update events that have no change in the object's metadata.generation field.
// The metadata.generation field of an object is incremented by the API server when writes are made to the spec field of an object.
// This allows a controller to ignore update events where the spec is unchanged, and only the metadata and/or status fields are changed.
//
// For CustomResource objects the Generation is only incremented when the status subresource is enabled.
//
// Caveats:
//
// * The assumption that the Generation is incremented only on writing to the spec does not hold for all APIs.
// E.g For Deployment objects the Generation is also incremented on writes to the metadata.annotations field.
// For object types other than CustomResources be sure to verify which fields will trigger a Generation increment when they are written to.
//
// * With this predicate, any update events with writes only to the status field will not be reconciled.
// So in the event that the status block is overwritten or wiped by someone else the controller will not self-correct to restore the correct status.
type GenerationChangedPredicate = TypedGenerationChangedPredicate[client.Object]

// TypedGenerationChangedPredicate implements a default update predicate function on Generation change.
//
// This predicate will skip update events that have no change in the object's metadata.generation field.
// The metadata.generation field of an object is incremented by the API server when writes are made to the spec field of an object.
// This allows a controller to ignore update events where the spec is unchanged, and only the metadata and/or status fields are changed.
//
// For CustomResource objects the Generation is only incremented when the status subresource is enabled.
//
// Caveats:
//
// * The assumption that the Generation is incremented only on writing to the spec does not hold for all APIs.
// E.g For Deployment objects the Generation is also incremented on writes to the metadata.annotations field.
// For object types other than CustomResources be sure to verify which fields will trigger a Generation increment when they are written to.
//
// * With this predicate, any update events with writes only to the status field will not be reconciled.
// So in the event that the status block is overwritten or wiped by someone else the controller will not self-correct to restore the correct status.
type TypedGenerationChangedPredicate[T metav1.Object] struct {
	TypedFuncs[T]
}

// Update implements default UpdateEvent filter for validating generation change.
func (TypedGenerationChangedPredicate[T]) Update(e event.TypedUpdateEvent[T]) bool {
	if isNil(e.ObjectOld) {
		log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if isNil(e.ObjectNew) {
		log.Error(nil, "Update event has no new object for update", "event", e)
		return false
	}

	return e.ObjectNew.GetGeneration() != e.ObjectOld.GetGeneration()
}

// AnnotationChangedPredicate implements a default update predicate function on annotation change.
//
// This predicate will skip update events that have no change in the object's annotation.
// It is intended to be used in conjunction with the GenerationChangedPredicate, as in the following example:
//
//	Controller.Watch(
//		&source.Kind{Type: v1.MyCustomKind},
//		&handler.EnqueueRequestForObject{},
//		predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))
//
// This is mostly useful for controllers that needs to trigger both when the resource's generation is incremented
// (i.e., when the resource' .spec changes), or an annotation changes (e.g., for a staging/alpha API).
type AnnotationChangedPredicate = TypedAnnotationChangedPredicate[client.Object]

// TypedAnnotationChangedPredicate implements a default update predicate function on annotation change.
type TypedAnnotationChangedPredicate[T metav1.Object] struct {
	TypedFuncs[T]
}

// Update implements default UpdateEvent filter for validating annotation change.
func (TypedAnnotationChangedPredicate[T]) Update(e event.TypedUpdateEvent[T]) bool {
	if isNil(e.ObjectOld) {
		log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if isNil(e.ObjectNew) {
		log.Error(nil, "Update event has no new object for update", "event", e)
		return false
	}

	return !maps.Equal(e.ObjectNew.GetAnnotations(), e.ObjectOld.GetAnnotations())
}

// LabelChangedPredicate implements a default update predicate function on label change.
//
// This predicate will skip update events that have no change in the object's label.
// It is intended to be used in conjunction with the GenerationChangedPredicate, as in the following example:
//
// Controller.Watch(
//
//	&source.Kind{Type: v1.MyCustomKind},
//	&handler.EnqueueRequestForObject{},
//	predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))
//
// This will be helpful when object's labels is carrying some extra specification information beyond object's spec,
// and the controller will be triggered if any valid spec change (not only in spec, but also in labels) happens.
type LabelChangedPredicate = TypedLabelChangedPredicate[client.Object]

// TypedLabelChangedPredicate implements a default update predicate function on label change.
type TypedLabelChangedPredicate[T metav1.Object] struct {
	TypedFuncs[T]
}

// Update implements default UpdateEvent filter for checking label change.
func (TypedLabelChangedPredicate[T]) Update(e event.TypedUpdateEvent[T]) bool {
	if isNil(e.ObjectOld) {
		log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if isNil(e.ObjectNew) {
		log.Error(nil, "Update event has no new object for update", "event", e)
		return false
	}

	return !maps.Equal(e.ObjectNew.GetLabels(), e.ObjectOld.GetLabels())
}

// And returns a composite predicate that implements a logical AND of the predicates passed to it.
func And[T any](predicates ...TypedPredicate[T]) TypedPredicate[T] {
	return and[T]{predicates}
}

type and[T any] struct {
	predicates []TypedPredicate[T]
}

func (a and[T]) Create(e event.TypedCreateEvent[T]) bool {
	for _, p := range a.predicates {
		if !p.Create(e) {
			return false
		}
	}
	return true
}

func (a and[T]) Update(e event.TypedUpdateEvent[T]) bool {
	for _, p := range a.predicates {
		if !p.Update(e) {
			return false
		}
	}
	return true
}

func (a and[T]) Delete(e event.TypedDeleteEvent[T]) bool {
	for _, p := range a.predicates {
		if !p.Delete(e) {
			return false
		}
	}
	return true
}

func (a and[T]) Generic(e event.TypedGenericEvent[T]) bool {
	for _, p := range a.predicates {
		if !p.Generic(e) {
			return false
		}
	}
	return true
}

// Or returns a composite predicate that implements a logical OR of the predicates passed to it.
func Or[T any](predicates ...TypedPredicate[T]) TypedPredicate[T] {
	return or[T]{predicates}
}

type or[T any] struct {
	predicates []TypedPredicate[T]
}

func (o or[T]) Create(e event.TypedCreateEvent[T]) bool {
	for _, p := range o.predicates {
		if p.Create(e) {
			return true
		}
	}
	return false
}

func (o or[T]) Update(e event.TypedUpdateEvent[T]) bool {
	for _, p := range o.predicates {
		if p.Update(e) {
			return true
		}
	}
	return false
}

func (o or[T]) Delete(e event.TypedDeleteEvent[T]) bool {
	for _, p := range o.predicates {
		if p.Delete(e) {
			return true
		}
	}
	return false
}

func (o or[T]) Generic(e event.TypedGenericEvent[T]) bool {
	for _, p := range o.predicates {
		if p.Generic(e) {
			return true
		}
	}
	return false
}

// Not returns a predicate that implements a logical NOT of the predicate passed to it.
func Not[T any](predicate TypedPredicate[T]) TypedPredicate[T] {
	return not[T]{predicate}
}

type not[T any] struct {
	predicate TypedPredicate[T]
}

func (n not[T]) Create(e event.TypedCreateEvent[T]) bool {
	return !n.predicate.Create(e)
}

func (n not[T]) Update(e event.TypedUpdateEvent[T]) bool {
	return !n.predicate.Update(e)
}

func (n not[T]) Delete(e event.TypedDeleteEvent[T]) bool {
	return !n.predicate.Delete(e)
}

func (n not[T]) Generic(e event.TypedGenericEvent[T]) bool {
	return !n.predicate.Generic(e)
}

// LabelSelectorPredicate constructs a Predicate from a LabelSelector.
// Only objects matching the LabelSelector will be admitted.
func LabelSelectorPredicate(s metav1.LabelSelector) (Predicate, error) {
	selector, err := metav1.LabelSelectorAsSelector(&s)
	if err != nil {
		return Funcs{}, err
	}
	return NewPredicateFuncs(func(o client.Object) bool {
		return selector.Matches(labels.Set(o.GetLabels()))
	}), nil
}

func isNil(arg any) bool {
	if v := reflect.ValueOf(arg); !v.IsValid() || ((v.Kind() == reflect.Ptr ||
		v.Kind() == reflect.Interface ||
		v.Kind() == reflect.Slice ||
		v.Kind() == reflect.Map ||
		v.Kind() == reflect.Chan ||
		v.Kind() == reflect.Func) && v.IsNil()) {
		return true
	}
	return false
}
