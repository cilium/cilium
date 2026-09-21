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

package config

import (
	"time"

	gatewayconfig "sigs.k8s.io/gateway-api/conformance/utils/config"
)

// InferenceExtensionTimeoutConfig embeds the upstream TimeoutConfig and adds
// extension-specific timeout values.
type InferenceExtensionTimeoutConfig struct {
	// All fields from gatewayconfig.TimeoutConfig will be available directly.
	gatewayconfig.TimeoutConfig

	// GeneralMustHaveConditionTimeout represents the maximum time to wait for an InferencePool, HttpRoute or other assets to have a specific condition.
	GeneralMustHaveConditionTimeout time.Duration

	// InferencePoolMustHaveConditionInterval represents the polling interval for checking an InferencePool's condition.
	InferencePoolMustHaveConditionInterval time.Duration

	// GatewayObjectPollInterval is the polling interval used when waiting for a Gateway object to appear.
	GatewayObjectPollInterval time.Duration

	// HTTPRouteConditionTimeout represents the maximum time to wait for an HTTPRoute to have a specific condition.
	HTTPRouteDeletionReconciliationTimeout time.Duration

	// ServiceUpdateTimeout represents the maximum time to wait for a service to be updated.
	ServiceUpdateTimeout time.Duration
}

// DefaultInferenceExtensionTimeoutConfig returns a new InferenceExtensionTimeoutConfig with default values.
func DefaultInferenceExtensionTimeoutConfig() InferenceExtensionTimeoutConfig {
	config := gatewayconfig.DefaultTimeoutConfig()
	config.HTTPRouteMustHaveCondition = 300 * time.Second
	config.RouteMustHaveParents = 300 * time.Second
	config.MaxTimeToConsistency = 300 * time.Second
	config.DefaultTestTimeout = 600 * time.Second
	return InferenceExtensionTimeoutConfig{
		TimeoutConfig:                          config, // Initialize embedded struct
		GeneralMustHaveConditionTimeout:        300 * time.Second,
		InferencePoolMustHaveConditionInterval: 1 * time.Second,
		GatewayObjectPollInterval:              1 * time.Second,
		HTTPRouteDeletionReconciliationTimeout: 5 * time.Second,
		ServiceUpdateTimeout:                   10 * time.Second,
	}
}
