/*
Copyright 2021 The Kubernetes Authors.

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

package admission

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
)

// CustomDefaulter defines functions for setting defaults on resources.
type CustomDefaulter interface {
	Default(ctx context.Context, obj runtime.Object) error
}

type defaulterOptions struct {
	removeUnknownOrOmitableFields bool
}

// DefaulterOption defines the type of a CustomDefaulter's option
type DefaulterOption func(*defaulterOptions)

// DefaulterRemoveUnknownOrOmitableFields makes the defaulter prune fields that are in the json object retrieved by the
// webhook but not in the local go type json representation. This happens for example when the CRD in the apiserver has
// fields that our go type doesn't know about, because it's outdated, or the field has a zero value and is `omitempty`.
func DefaulterRemoveUnknownOrOmitableFields(o *defaulterOptions) {
	o.removeUnknownOrOmitableFields = true
}

// WithCustomDefaulter creates a new Webhook for a CustomDefaulter interface.
func WithCustomDefaulter(scheme *runtime.Scheme, obj runtime.Object, defaulter CustomDefaulter, opts ...DefaulterOption) *Webhook {
	options := &defaulterOptions{}
	for _, o := range opts {
		o(options)
	}
	return &Webhook{
		Handler: &defaulterForType{
			object:                        obj,
			defaulter:                     defaulter,
			decoder:                       NewDecoder(scheme),
			removeUnknownOrOmitableFields: options.removeUnknownOrOmitableFields,
		},
	}
}

type defaulterForType struct {
	defaulter                     CustomDefaulter
	object                        runtime.Object
	decoder                       Decoder
	removeUnknownOrOmitableFields bool
}

// Handle handles admission requests.
func (h *defaulterForType) Handle(ctx context.Context, req Request) Response {
	if h.decoder == nil {
		panic("decoder should never be nil")
	}
	if h.defaulter == nil {
		panic("defaulter should never be nil")
	}
	if h.object == nil {
		panic("object should never be nil")
	}

	// Always skip when a DELETE operation received in custom mutation handler.
	if req.Operation == admissionv1.Delete {
		return Response{AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Code: http.StatusOK,
			},
		}}
	}

	ctx = NewContextWithRequest(ctx, req)

	// Get the object in the request
	obj := h.object.DeepCopyObject()
	if err := h.decoder.Decode(req, obj); err != nil {
		return Errored(http.StatusBadRequest, err)
	}

	// Keep a copy of the object if needed
	var originalObj runtime.Object
	if !h.removeUnknownOrOmitableFields {
		originalObj = obj.DeepCopyObject()
	}

	// Default the object
	if err := h.defaulter.Default(ctx, obj); err != nil {
		var apiStatus apierrors.APIStatus
		if errors.As(err, &apiStatus) {
			return validationResponseFromStatus(false, apiStatus.Status())
		}
		return Denied(err.Error())
	}

	// Create the patch
	marshalled, err := json.Marshal(obj)
	if err != nil {
		return Errored(http.StatusInternalServerError, err)
	}

	handlerResponse := PatchResponseFromRaw(req.Object.Raw, marshalled)
	if !h.removeUnknownOrOmitableFields {
		handlerResponse = h.dropSchemeRemovals(handlerResponse, originalObj, req.Object.Raw)
	}
	return handlerResponse
}

func (h *defaulterForType) dropSchemeRemovals(r Response, original runtime.Object, raw []byte) Response {
	const opRemove = "remove"
	if !r.Allowed || r.PatchType == nil {
		return r
	}

	// If we don't have removals in the patch.
	if !slices.ContainsFunc(r.Patches, func(o jsonpatch.JsonPatchOperation) bool { return o.Operation == opRemove }) {
		return r
	}

	// Get the raw to original patch
	marshalledOriginal, err := json.Marshal(original)
	if err != nil {
		return Errored(http.StatusInternalServerError, err)
	}

	patchOriginal, err := jsonpatch.CreatePatch(raw, marshalledOriginal)
	if err != nil {
		return Errored(http.StatusInternalServerError, err)
	}
	removedByScheme := sets.New(slices.DeleteFunc(patchOriginal, func(p jsonpatch.JsonPatchOperation) bool { return p.Operation != opRemove })...)

	r.Patches = slices.DeleteFunc(r.Patches, func(p jsonpatch.JsonPatchOperation) bool {
		return p.Operation == opRemove && removedByScheme.Has(p)
	})

	if len(r.Patches) == 0 {
		r.PatchType = nil
	}
	return r
}
