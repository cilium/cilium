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

// Warnings represents warning messages.
type Warnings []string

// Validator defines functions for validating an operation.
// The custom resource kind which implements this interface can validate itself.
// To validate the custom resource with another specific struct, use CustomValidator instead.
type Validator interface {
	runtime.Object

	// ValidateCreate validates the object on creation.
	// The optional warnings will be added to the response as warning messages.
	// Return an error if the object is invalid.
	ValidateCreate() (warnings Warnings, err error)

	// ValidateUpdate validates the object on update. The oldObj is the object before the update.
	// The optional warnings will be added to the response as warning messages.
	// Return an error if the object is invalid.
	ValidateUpdate(old runtime.Object) (warnings Warnings, err error)

	// ValidateDelete validates the object on deletion.
	// The optional warnings will be added to the response as warning messages.
	// Return an error if the object is invalid.
	ValidateDelete() (warnings Warnings, err error)
}

// ValidatingWebhookFor creates a new Webhook for validating the provided type.
func ValidatingWebhookFor(scheme *runtime.Scheme, validator Validator) *Webhook {
	return &Webhook{
		Handler: &validatingHandler{validator: validator, decoder: NewDecoder(scheme)},
	}
}

type validatingHandler struct {
	validator Validator
	decoder   *Decoder
}

// Handle handles admission requests.
func (h *validatingHandler) Handle(ctx context.Context, req Request) Response {
	if h.decoder == nil {
		panic("decoder should never be nil")
	}
	if h.validator == nil {
		panic("validator should never be nil")
	}
	// Get the object in the request
	obj := h.validator.DeepCopyObject().(Validator)

	var err error
	var warnings []string

	switch req.Operation {
	case v1.Connect:
		// No validation for connect requests.
		// TODO(vincepri): Should we validate CONNECT requests? In what cases?
	case v1.Create:
		if err = h.decoder.Decode(req, obj); err != nil {
			return Errored(http.StatusBadRequest, err)
		}

		warnings, err = obj.ValidateCreate()
	case v1.Update:
		oldObj := obj.DeepCopyObject()

		err = h.decoder.DecodeRaw(req.Object, obj)
		if err != nil {
			return Errored(http.StatusBadRequest, err)
		}
		err = h.decoder.DecodeRaw(req.OldObject, oldObj)
		if err != nil {
			return Errored(http.StatusBadRequest, err)
		}

		warnings, err = obj.ValidateUpdate(oldObj)
	case v1.Delete:
		// In reference to PR: https://github.com/kubernetes/kubernetes/pull/76346
		// OldObject contains the object being deleted
		err = h.decoder.DecodeRaw(req.OldObject, obj)
		if err != nil {
			return Errored(http.StatusBadRequest, err)
		}

		warnings, err = obj.ValidateDelete()
	default:
		return Errored(http.StatusBadRequest, fmt.Errorf("unknown operation %q", req.Operation))
	}

	if err != nil {
		var apiStatus apierrors.APIStatus
		if errors.As(err, &apiStatus) {
			return validationResponseFromStatus(false, apiStatus.Status()).WithWarnings(warnings...)
		}
		return Denied(err.Error()).WithWarnings(warnings...)
	}
	return Allowed("").WithWarnings(warnings...)
}
