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
	"errors"
	"fmt"
	"net/http"

	v1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
)

// CustomValidator defines functions for validating an operation.
// The object to be validated is passed into methods as a parameter.
type CustomValidator interface {

	// ValidateCreate validates the object on creation.
	// The optional warnings will be added to the response as warning messages.
	// Return an error if the object is invalid.
	ValidateCreate(ctx context.Context, obj runtime.Object) (warnings Warnings, err error)

	// ValidateUpdate validates the object on update.
	// The optional warnings will be added to the response as warning messages.
	// Return an error if the object is invalid.
	ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (warnings Warnings, err error)

	// ValidateDelete validates the object on deletion.
	// The optional warnings will be added to the response as warning messages.
	// Return an error if the object is invalid.
	ValidateDelete(ctx context.Context, obj runtime.Object) (warnings Warnings, err error)
}

// WithCustomValidator creates a new Webhook for validating the provided type.
func WithCustomValidator(scheme *runtime.Scheme, obj runtime.Object, validator CustomValidator) *Webhook {
	return &Webhook{
		Handler: &validatorForType{object: obj, validator: validator, decoder: NewDecoder(scheme)},
	}
}

type validatorForType struct {
	validator CustomValidator
	object    runtime.Object
	decoder   *Decoder
}

// Handle handles admission requests.
func (h *validatorForType) Handle(ctx context.Context, req Request) Response {
	if h.decoder == nil {
		panic("decoder should never be nil")
	}
	if h.validator == nil {
		panic("validator should never be nil")
	}
	if h.object == nil {
		panic("object should never be nil")
	}

	ctx = NewContextWithRequest(ctx, req)

	// Get the object in the request
	obj := h.object.DeepCopyObject()

	var err error
	var warnings []string

	switch req.Operation {
	case v1.Connect:
		// No validation for connect requests.
		// TODO(vincepri): Should we validate CONNECT requests? In what cases?
	case v1.Create:
		if err := h.decoder.Decode(req, obj); err != nil {
			return Errored(http.StatusBadRequest, err)
		}

		warnings, err = h.validator.ValidateCreate(ctx, obj)
	case v1.Update:
		oldObj := obj.DeepCopyObject()
		if err := h.decoder.DecodeRaw(req.Object, obj); err != nil {
			return Errored(http.StatusBadRequest, err)
		}
		if err := h.decoder.DecodeRaw(req.OldObject, oldObj); err != nil {
			return Errored(http.StatusBadRequest, err)
		}

		warnings, err = h.validator.ValidateUpdate(ctx, oldObj, obj)
	case v1.Delete:
		// In reference to PR: https://github.com/kubernetes/kubernetes/pull/76346
		// OldObject contains the object being deleted
		if err := h.decoder.DecodeRaw(req.OldObject, obj); err != nil {
			return Errored(http.StatusBadRequest, err)
		}

		warnings, err = h.validator.ValidateDelete(ctx, obj)
	default:
		return Errored(http.StatusBadRequest, fmt.Errorf("unknown operation %q", req.Operation))
	}

	// Check the error message first.
	if err != nil {
		var apiStatus apierrors.APIStatus
		if errors.As(err, &apiStatus) {
			return validationResponseFromStatus(false, apiStatus.Status()).WithWarnings(warnings...)
		}
		return Denied(err.Error()).WithWarnings(warnings...)
	}

	// Return allowed if everything succeeded.
	return Allowed("").WithWarnings(warnings...)
}
