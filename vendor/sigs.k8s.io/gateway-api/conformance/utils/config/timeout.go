/*
Copyright 2022 The Kubernetes Authors.

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

package config

import "time"

type TimeoutConfig struct {
	// CreateTimeout represents the maximum time for a Kubernetes object to be created.
	// Max value for conformant implementation: None
	CreateTimeout time.Duration

	// DeleteTimeout represents the maximum time for a Kubernetes object to be deleted.
	// Max value for conformant implementation: None
	DeleteTimeout time.Duration

	// GetTimeout represents the maximum time to get a Kubernetes object.
	// Max value for conformant implementation: None
	GetTimeout time.Duration

	// GatewayMustHaveAddress represents the maximum time for at least one IP Address has been set in the status of a Gateway.
	// Max value for conformant implementation: None
	GatewayMustHaveAddress time.Duration

	// GatewayStatusMustHaveListeners represents the maximum time for a Gateway to have listeners in status that match the expected listeners.
	// Max value for conformant implementation: None
	GatewayStatusMustHaveListeners time.Duration

	// GWCMustBeAccepted represents the maximum time for a GatewayClass to have an Accepted condition set to true.
	// Max value for conformant implementation: None
	GWCMustBeAccepted time.Duration

	// HTTPRouteMustNotHaveParents represents the maximum time for an HTTPRoute to have either no parents or a single parent that is not accepted.
	// Max value for conformant implementation: None
	HTTPRouteMustNotHaveParents time.Duration

	// HTTPRouteMustHaveCondition represents the maximum time for an HTTPRoute to have the supplied Condition.
	// Max value for conformant implementation: None
	HTTPRouteMustHaveCondition time.Duration

	// RouteMustHaveParents represents the maximum time for an xRoute to have parents in status that match the expected parents.
	// Max value for conformant implementation: None
	RouteMustHaveParents time.Duration

	// ManifestFetchTimeout represents the maximum time for getting content from a https:// URL.
	// Max value for conformant implementation: None
	ManifestFetchTimeout time.Duration

	// MaxTimeToConsistency is the maximum time for requiredConsecutiveSuccesses (default 3) requests to succeed in a row before failing the test.
	// Max value for conformant implementation: 30 seconds
	MaxTimeToConsistency time.Duration

	// NamespacesMustBeReady represents the maximum time for all Pods and Gateways in a namespaces to be marked as ready.
	// Max value for conformant implementation: None
	NamespacesMustBeReady time.Duration

	// RequestTimeout represents the maximum time for making an HTTP Request with the roundtripper.
	// Max value for conformant implementation: None
	RequestTimeout time.Duration

	// RequiredConsecutiveSuccesses is the number of requests that must succeed in a row
	// to consider a response "consistent" before making additional assertions on the response body.
	// If this number is not reached within MaxTimeToConsistency, the test will fail.
	RequiredConsecutiveSuccesses int
}

// DefaultTimeoutConfig populates a TimeoutConfig with the default values.
func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{
		CreateTimeout:                  60 * time.Second,
		DeleteTimeout:                  10 * time.Second,
		GetTimeout:                     10 * time.Second,
		GatewayMustHaveAddress:         180 * time.Second,
		GatewayStatusMustHaveListeners: 60 * time.Second,
		GWCMustBeAccepted:              180 * time.Second,
		HTTPRouteMustNotHaveParents:    60 * time.Second,
		HTTPRouteMustHaveCondition:     60 * time.Second,
		RouteMustHaveParents:           60 * time.Second,
		ManifestFetchTimeout:           10 * time.Second,
		MaxTimeToConsistency:           30 * time.Second,
		NamespacesMustBeReady:          300 * time.Second,
		RequestTimeout:                 10 * time.Second,
		RequiredConsecutiveSuccesses:   3,
	}
}

func SetupTimeoutConfig(timeoutConfig *TimeoutConfig) {
	defaultTimeoutConfig := DefaultTimeoutConfig()
	if timeoutConfig.CreateTimeout == 0 {
		timeoutConfig.CreateTimeout = defaultTimeoutConfig.CreateTimeout
	}
	if timeoutConfig.DeleteTimeout == 0 {
		timeoutConfig.DeleteTimeout = defaultTimeoutConfig.DeleteTimeout
	}
	if timeoutConfig.GetTimeout == 0 {
		timeoutConfig.GetTimeout = defaultTimeoutConfig.GetTimeout
	}
	if timeoutConfig.GatewayMustHaveAddress == 0 {
		timeoutConfig.GatewayMustHaveAddress = defaultTimeoutConfig.GatewayMustHaveAddress
	}
	if timeoutConfig.GatewayStatusMustHaveListeners == 0 {
		timeoutConfig.GatewayStatusMustHaveListeners = defaultTimeoutConfig.GatewayStatusMustHaveListeners
	}
	if timeoutConfig.GWCMustBeAccepted == 0 {
		timeoutConfig.GWCMustBeAccepted = defaultTimeoutConfig.GWCMustBeAccepted
	}
	if timeoutConfig.HTTPRouteMustNotHaveParents == 0 {
		timeoutConfig.HTTPRouteMustNotHaveParents = defaultTimeoutConfig.HTTPRouteMustNotHaveParents
	}
	if timeoutConfig.HTTPRouteMustHaveCondition == 0 {
		timeoutConfig.HTTPRouteMustHaveCondition = defaultTimeoutConfig.HTTPRouteMustHaveCondition
	}
	if timeoutConfig.RouteMustHaveParents == 0 {
		timeoutConfig.RouteMustHaveParents = defaultTimeoutConfig.RouteMustHaveParents
	}
	if timeoutConfig.ManifestFetchTimeout == 0 {
		timeoutConfig.ManifestFetchTimeout = defaultTimeoutConfig.ManifestFetchTimeout
	}
	if timeoutConfig.MaxTimeToConsistency == 0 {
		timeoutConfig.MaxTimeToConsistency = defaultTimeoutConfig.MaxTimeToConsistency
	}
	if timeoutConfig.NamespacesMustBeReady == 0 {
		timeoutConfig.NamespacesMustBeReady = defaultTimeoutConfig.NamespacesMustBeReady
	}
	if timeoutConfig.RequestTimeout == 0 {
		timeoutConfig.RequestTimeout = defaultTimeoutConfig.RequestTimeout
	}
}
