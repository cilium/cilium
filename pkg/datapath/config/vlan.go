// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// +deepequal-gen=true
type VLANFilter struct {
	Entries  []VLANFilterEntry
	AllowAll bool
}

// +deepequal-gen=true
type VLANFilterEntry struct {
	IfIndex int
	VLAN    uint16
}
