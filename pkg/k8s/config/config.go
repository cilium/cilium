// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"github.com/cilium/cilium/pkg/defaults"
)

// Configuration is the configuration interface for the k8s package
type Configuration interface {
	K8sAPIDiscoveryEnabled() bool

	K8sLeasesFallbackDiscoveryEnabled() bool
}

// DefaultConfiguration is an implementation of Configuration with default
// values
type DefaultConfiguration struct{}

// NewDefaultConfiguration returns an implementation of Configuration with
// default values
func NewDefaultConfiguration() Configuration {
	return &DefaultConfiguration{}
}

// K8sAPIDiscoveryEnabled returns true if API discovery of API groups and
// resources is enabled
func (d *DefaultConfiguration) K8sAPIDiscoveryEnabled() bool {
	return defaults.K8sEnableAPIDiscovery
}

// K8sLeasesFallbackDiscoveryEnabled returns true if we should fallback to direct API
// probing when checking for support of Leases in case Discovery API fails to discover
// required groups.
func (d *DefaultConfiguration) K8sLeasesFallbackDiscoveryEnabled() bool {
	return defaults.K8sEnableLeasesFallbackDiscovery
}
