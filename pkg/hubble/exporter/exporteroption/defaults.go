// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package exporteroption

// Default specifies default values for Hubble exporter options.
var Default = Options{
	Path:       "", // An empty string disables Hubble export.
	MaxSizeMB:  10,
	MaxBackups: 5,
	Compress:   false,
}
