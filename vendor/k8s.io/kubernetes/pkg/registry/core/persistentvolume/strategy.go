/*
Copyright 2014 The Kubernetes Authors.

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

package persistentvolume

import (
	"fmt"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/validation"
	volumevalidation "k8s.io/kubernetes/pkg/volume/validation"
)

// persistentvolumeStrategy implements behavior for PersistentVolume objects
type persistentvolumeStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// Strategy is the default logic that applies when creating and updating PersistentVolume
// objects via the REST API.
var Strategy = persistentvolumeStrategy{api.Scheme, names.SimpleNameGenerator}

func (persistentvolumeStrategy) NamespaceScoped() bool {
	return false
}

// ResetBeforeCreate clears the Status field which is not allowed to be set by end users on creation.
func (persistentvolumeStrategy) PrepareForCreate(ctx genericapirequest.Context, obj runtime.Object) {
	pv := obj.(*api.PersistentVolume)
	pv.Status = api.PersistentVolumeStatus{}
}

func (persistentvolumeStrategy) Validate(ctx genericapirequest.Context, obj runtime.Object) field.ErrorList {
	persistentvolume := obj.(*api.PersistentVolume)
	errorList := validation.ValidatePersistentVolume(persistentvolume)
	return append(errorList, volumevalidation.ValidatePersistentVolume(persistentvolume)...)
}

// Canonicalize normalizes the object after validation.
func (persistentvolumeStrategy) Canonicalize(obj runtime.Object) {
}

func (persistentvolumeStrategy) AllowCreateOnUpdate() bool {
	return false
}

// PrepareForUpdate sets the Status fields which is not allowed to be set by an end user updating a PV
func (persistentvolumeStrategy) PrepareForUpdate(ctx genericapirequest.Context, obj, old runtime.Object) {
	newPv := obj.(*api.PersistentVolume)
	oldPv := old.(*api.PersistentVolume)
	newPv.Status = oldPv.Status
}

func (persistentvolumeStrategy) ValidateUpdate(ctx genericapirequest.Context, obj, old runtime.Object) field.ErrorList {
	newPv := obj.(*api.PersistentVolume)
	errorList := validation.ValidatePersistentVolume(newPv)
	errorList = append(errorList, volumevalidation.ValidatePersistentVolume(newPv)...)
	return append(errorList, validation.ValidatePersistentVolumeUpdate(newPv, old.(*api.PersistentVolume))...)
}

func (persistentvolumeStrategy) AllowUnconditionalUpdate() bool {
	return true
}

type persistentvolumeStatusStrategy struct {
	persistentvolumeStrategy
}

var StatusStrategy = persistentvolumeStatusStrategy{Strategy}

// PrepareForUpdate sets the Spec field which is not allowed to be changed when updating a PV's Status
func (persistentvolumeStatusStrategy) PrepareForUpdate(ctx genericapirequest.Context, obj, old runtime.Object) {
	newPv := obj.(*api.PersistentVolume)
	oldPv := old.(*api.PersistentVolume)
	newPv.Spec = oldPv.Spec
}

func (persistentvolumeStatusStrategy) ValidateUpdate(ctx genericapirequest.Context, obj, old runtime.Object) field.ErrorList {
	return validation.ValidatePersistentVolumeStatusUpdate(obj.(*api.PersistentVolume), old.(*api.PersistentVolume))
}

// GetAttrs returns labels and fields of a given object for filtering purposes.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, bool, error) {
	persistentvolumeObj, ok := obj.(*api.PersistentVolume)
	if !ok {
		return nil, nil, false, fmt.Errorf("not a persistentvolume")
	}
	return labels.Set(persistentvolumeObj.Labels), PersistentVolumeToSelectableFields(persistentvolumeObj), persistentvolumeObj.Initializers != nil, nil
}

// MatchPersistentVolume returns a generic matcher for a given label and field selector.
func MatchPersistentVolumes(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// PersistentVolumeToSelectableFields returns a field set that represents the object
func PersistentVolumeToSelectableFields(persistentvolume *api.PersistentVolume) fields.Set {
	objectMetaFieldsSet := generic.ObjectMetaFieldsSet(&persistentvolume.ObjectMeta, false)
	specificFieldsSet := fields.Set{
		// This is a bug, but we need to support it for backward compatibility.
		"name": persistentvolume.Name,
	}
	return generic.MergeFieldsSets(objectMetaFieldsSet, specificFieldsSet)
}
