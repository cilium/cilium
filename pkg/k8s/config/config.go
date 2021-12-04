// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package config

import (
	"github.com/cilium/cilium/pkg/defaults"
)

// Configuration is the configuration interface for the k8s package
type Configuration interface {
	K8sAPIDiscoveryEnabled() bool
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
