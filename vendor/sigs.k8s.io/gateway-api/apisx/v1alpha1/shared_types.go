/*
Copyright 2025 The Kubernetes Authors.

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

package v1alpha1

import (
	v1 "sigs.k8s.io/gateway-api/apis/v1"
)

type (
	Duration                   = v1.Duration
	PolicyStatus               = v1.PolicyStatus
	LocalPolicyTargetReference = v1.LocalPolicyTargetReference
	SessionPersistence         = v1.SessionPersistence
)

// RequestRate expresses a rate of requests over a given period of time.
type RequestRate struct {
	// Count specifies the number of requests per time interval.
	//
	// Support: Extended
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	// +optional
	Count *int `json:"count,omitempty"`

	// Interval specifies the divisor of the rate of requests, the amount of
	// time during which the given count of requests occur.
	//
	// Support: Extended
	// +kubebuilder:validation:XValidation:message="interval cannot be greater than one hour",rule="!(duration(self) == duration('0s') || duration(self) > duration('1h'))"
	// +optional
	Interval *Duration `json:"interval,omitempty"`
}
