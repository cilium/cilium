// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observeroption

import "github.com/cilium/cilium/pkg/hubble/container"

// Default serves only as reference point for default values. Very useful for
// the CLI to pick these up instead of defining own defaults that need to be
// kept in sync.
var Default = Options{
	MaxFlows:      container.Capacity4095, // 4095
	MonitorBuffer: 1024,
}
