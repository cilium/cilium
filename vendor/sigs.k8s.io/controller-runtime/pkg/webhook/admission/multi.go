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
	"encoding/json"
	"fmt"
	"net/http"

	jsonpatch "gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type multiMutating []Handler

func (hs multiMutating) Handle(ctx context.Context, req Request) Response {
	patches := []jsonpatch.JsonPatchOperation{}
	warnings := []string{}
	for _, handler := range hs {
		resp := handler.Handle(ctx, req)
		if !resp.Allowed {
			return resp
		}
		if resp.PatchType != nil && *resp.PatchType != admissionv1.PatchTypeJSONPatch {
			return Errored(http.StatusInternalServerError,
				fmt.Errorf("unexpected patch type returned by the handler: %v, only allow: %v",
					resp.PatchType, admissionv1.PatchTypeJSONPatch))
		}
		patches = append(patches, resp.Patches...)
		warnings = append(warnings, resp.Warnings...)
	}
	var err error
	marshaledPatch, err := json.Marshal(patches)
	if err != nil {
		return Errored(http.StatusBadRequest, fmt.Errorf("error when marshaling the patch: %w", err))
	}
	return Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Code: http.StatusOK,
			},
			Patch:     marshaledPatch,
			Warnings:  warnings,
			PatchType: func() *admissionv1.PatchType { pt := admissionv1.PatchTypeJSONPatch; return &pt }(),
		},
	}
}

// MultiMutatingHandler combines multiple mutating webhook handlers into a single
// mutating webhook handler.  Handlers are called in sequential order, and the first
// `allowed: false`	response may short-circuit the rest.  Users must take care to
// ensure patches are disjoint.
func MultiMutatingHandler(handlers ...Handler) Handler {
	return multiMutating(handlers)
}

type multiValidating []Handler

func (hs multiValidating) Handle(ctx context.Context, req Request) Response {
	warnings := []string{}
	for _, handler := range hs {
		resp := handler.Handle(ctx, req)
		if !resp.Allowed {
			return resp
		}
		warnings = append(warnings, resp.Warnings...)
	}
	return Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Code: http.StatusOK,
			},
			Warnings: warnings,
		},
	}
}

// MultiValidatingHandler combines multiple validating webhook handlers into a single
// validating webhook handler.  Handlers are called in sequential order, and the first
// `allowed: false`	response may short-circuit the rest.
func MultiValidatingHandler(handlers ...Handler) Handler {
	return multiValidating(handlers)
}
