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
type TypedPredicate[object any] interface {
	// Create returns true if the Create event should be processed
	Create(event.TypedCreateEvent[object]) bool

	// Delete returns true if the Delete event should be processed
	Delete(event.TypedDeleteEvent[object]) bool

	// Update returns true if the Update event should be processed
	Update(event.TypedUpdateEvent[object]) bool

	// Generic returns true if the Generic event should be processed
	Generic(event.TypedGenericEvent[object]) bool
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
type TypedFuncs[object any] struct {
	// Create returns true if the Create event should be processed
	CreateFunc func(event.TypedCreateEvent[object]) bool

	// Delete returns true if the Delete event should be processed
	DeleteFunc func(event.TypedDeleteEvent[object]) bool

	// Update returns true if the Update event should be processed
	UpdateFunc func(event.TypedUpdateEvent[object]) bool

	// Generic returns true if the Generic event should be processed
	GenericFunc func(event.TypedGenericEvent[object]) bool
}

// Create implements Predicate.
func (p TypedFuncs[object]) Create(e event.TypedCreateEvent[object]) bool {
	if p.CreateFunc != nil {
		return p.CreateFunc(e)
	}
	return true
}

// Delete implements Predicate.
func (p TypedFuncs[object]) Delete(e event.TypedDeleteEvent[object]) bool {
	if p.DeleteFunc != nil {
		return p.DeleteFunc(e)
	}
	return true
}

// Update implements Predicate.
func (p TypedFuncs[object]) Update(e event.TypedUpdateEvent[object]) bool {
	if p.UpdateFunc != nil {
		return p.UpdateFunc(e)
	}
	return true
}

// Generic implements Predicate.
func (p TypedFuncs[object]) Generic(e event.TypedGenericEvent[object]) bool {
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
func NewTypedPredicateFuncs[object any](filter func(object object) bool) TypedFuncs[object] {
	return TypedFuncs[object]{
		CreateFunc: func(e event.TypedCreateEvent[object]) bool {
			return filter(e.Object)
		},
		UpdateFunc: func(e event.TypedUpdateEvent[object]) bool {
			return filter(e.ObjectNew)
		},
		DeleteFunc: func(e event.TypedDeleteEvent[object]) bool {
			return filter(e.Object)
		},
		GenericFunc: func(e event.TypedGenericEvent[object]) bool {
			return filter(e.Object)
		},
	}
}

// ResourceVersionChangedPredicate implements a default update predicate function on resource version change.
type ResourceVersionChangedPredicate = TypedResourceVersionChangedPredicate[client.Object]

// TypedResourceVersionChangedPredicate implements a default update predicate function on resource version change.
type TypedResourceVersionChangedPredicate[T metav1.Object] struct {
	TypedFuncs[T]
}

// Update implements default UpdateEvent filter for validating resource version change.
func (TypedResourceVersionChangedPredicate[T]) Update(e event.TypedUpdateEvent[T]) bool {
	if isNil(e.ObjectOld) {
		log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if isNil(e.ObjectNew) {
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
type TypedGenerationChangedPredicate[object metav1.Object] struct {
	TypedFuncs[object]
}

// Update implements default UpdateEvent filter for validating generation change.
func (TypedGenerationChangedPredicate[object]) Update(e event.TypedUpdateEvent[object]) bool {
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
type TypedAnnotationChangedPredicate[object metav1.Object] struct {
	TypedFuncs[object]
}

// Update implements default UpdateEvent filter for validating annotation change.
func (TypedAnnotationChangedPredicate[object]) Update(e event.TypedUpdateEvent[object]) bool {
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
type TypedLabelChangedPredicate[object metav1.Object] struct {
	TypedFuncs[object]
}

// Update implements default UpdateEvent filter for checking label change.
func (TypedLabelChangedPredicate[object]) Update(e event.TypedUpdateEvent[object]) bool {
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
func And[object any](predicates ...TypedPredicate[object]) TypedPredicate[object] {
	return and[object]{predicates}
}

type and[object any] struct {
	predicates []TypedPredicate[object]
}

func (a and[object]) Create(e event.TypedCreateEvent[object]) bool {
	for _, p := range a.predicates {
		if !p.Create(e) {
			return false
		}
	}
	return true
}

func (a and[object]) Update(e event.TypedUpdateEvent[object]) bool {
	for _, p := range a.predicates {
		if !p.Update(e) {
			return false
		}
	}
	return true
}

func (a and[object]) Delete(e event.TypedDeleteEvent[object]) bool {
	for _, p := range a.predicates {
		if !p.Delete(e) {
			return false
		}
	}
	return true
}

func (a and[object]) Generic(e event.TypedGenericEvent[object]) bool {
	for _, p := range a.predicates {
		if !p.Generic(e) {
			return false
		}
	}
	return true
}

// Or returns a composite predicate that implements a logical OR of the predicates passed to it.
func Or[object any](predicates ...TypedPredicate[object]) TypedPredicate[object] {
	return or[object]{predicates}
}

type or[object any] struct {
	predicates []TypedPredicate[object]
}

func (o or[object]) Create(e event.TypedCreateEvent[object]) bool {
	for _, p := range o.predicates {
		if p.Create(e) {
			return true
		}
	}
	return false
}

func (o or[object]) Update(e event.TypedUpdateEvent[object]) bool {
	for _, p := range o.predicates {
		if p.Update(e) {
			return true
		}
	}
	return false
}

func (o or[object]) Delete(e event.TypedDeleteEvent[object]) bool {
	for _, p := range o.predicates {
		if p.Delete(e) {
			return true
		}
	}
	return false
}

func (o or[object]) Generic(e event.TypedGenericEvent[object]) bool {
	for _, p := range o.predicates {
		if p.Generic(e) {
			return true
		}
	}
	return false
}

// Not returns a predicate that implements a logical NOT of the predicate passed to it.
func Not[object any](predicate TypedPredicate[object]) TypedPredicate[object] {
	return not[object]{predicate}
}

type not[object any] struct {
	predicate TypedPredicate[object]
}

func (n not[object]) Create(e event.TypedCreateEvent[object]) bool {
	return !n.predicate.Create(e)
}

func (n not[object]) Update(e event.TypedUpdateEvent[object]) bool {
	return !n.predicate.Update(e)
}

func (n not[object]) Delete(e event.TypedDeleteEvent[object]) bool {
	return !n.predicate.Delete(e)
}

func (n not[object]) Generic(e event.TypedGenericEvent[object]) bool {
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
