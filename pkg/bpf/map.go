// Copyright 2016-2021 Authors of Cilium
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

package bpf

import (
	"regexp"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
)

// MapType is an enumeration for valid BPF map types
type MapType int

// This enumeration must be in sync with enum bpf_map_type in <linux/bpf.h>
const (
	MapTypeUnspec MapType = iota
	MapTypeHash
	MapTypeArray
	MapTypeProgArray
	MapTypePerfEventArray
	MapTypePerCPUHash
	MapTypePerCPUArray
	MapTypeStackTrace
	MapTypeCgroupArray
	MapTypeLRUHash
	MapTypeLRUPerCPUHash
	MapTypeLPMTrie
	MapTypeArrayOfMaps
	MapTypeHashOfMaps
	MapTypeDevMap
	MapTypeSockMap
	MapTypeCPUMap
	MapTypeXSKMap
	MapTypeSockHash
	// MapTypeMaximum is the maximum supported known map type.
	MapTypeMaximum

	// maxSyncErrors is the maximum consecutive errors syncing before the
	// controller bails out
	maxSyncErrors = 512

	// errorResolverSchedulerMinInterval is the minimum interval for the
	// error resolver to be scheduled. This minimum interval ensures not to
	// overschedule if a large number of updates fail in a row.
	errorResolverSchedulerMinInterval = 5 * time.Second

	// errorResolverSchedulerDelay is the delay to update the controller
	// after determination that a run is needed. The delay allows to
	// schedule the resolver after series of updates have failed.
	errorResolverSchedulerDelay = 200 * time.Millisecond
)

var (
	mapControllers = controller.NewManager()

	supportedMapTypes *probes.MapTypes
)

func (t MapType) String() string {
	switch t {
	case MapTypeHash:
		return "Hash"
	case MapTypeArray:
		return "Array"
	case MapTypeProgArray:
		return "Program array"
	case MapTypePerfEventArray:
		return "Event array"
	case MapTypePerCPUHash:
		return "Per-CPU hash"
	case MapTypePerCPUArray:
		return "Per-CPU array"
	case MapTypeStackTrace:
		return "Stack trace"
	case MapTypeCgroupArray:
		return "Cgroup array"
	case MapTypeLRUHash:
		return "LRU hash"
	case MapTypeLRUPerCPUHash:
		return "LRU per-CPU hash"
	case MapTypeLPMTrie:
		return "Longest prefix match trie"
	case MapTypeArrayOfMaps:
		return "Array of maps"
	case MapTypeHashOfMaps:
		return "Hash of maps"
	case MapTypeDevMap:
		return "Device Map"
	case MapTypeSockMap:
		return "Socket Map"
	case MapTypeCPUMap:
		return "CPU Redirect Map"
	case MapTypeSockHash:
		return "Socket Hash"
	}

	return "Unknown"
}

func (t MapType) allowsPreallocation() bool {
	return t != MapTypeLPMTrie
}

func (t MapType) requiresPreallocation() bool {
	switch t {
	case MapTypeHash, MapTypePerCPUHash, MapTypeLPMTrie, MapTypeHashOfMaps:
		return false
	}
	return true
}

// DesiredAction is the action to be performed on the BPF map
type DesiredAction int

const (
	// OK indicates that to further action is required and the entry is in
	// sync
	OK DesiredAction = iota

	// Insert indicates that the entry needs to be created or updated
	Insert

	// Delete indicates that the entry needs to be deleted
	Delete
)

func (d DesiredAction) String() string {
	switch d {
	case OK:
		return "sync"
	case Insert:
		return "to-be-inserted"
	case Delete:
		return "to-be-deleted"
	default:
		return "unknown"
	}
}

// GetMapType determines whether the specified map type is supported by the
// kernel (as determined by bpftool feature checks), and if the map type is not
// supported, returns a more primitive map type that may be used to implement
// the map on older implementations. Otherwise, returns the specified map type.
func GetMapType(t MapType) MapType {
	// If the supported map types have not been set, default to the system
	// prober. This path enables unit tests to mock out the supported map
	// types.
	if supportedMapTypes == nil {
		setMapTypesFromProber(probes.NewProbeManager())
	}
	switch t {
	case MapTypeLPMTrie:
		fallthrough
	case MapTypeLRUHash:
		if !supportedMapTypes.HaveLruHashMapType {
			return MapTypeHash
		}
	}
	return t
}

// setMapTypesFromProber initializes the supported map types from the given
// prober. This function is useful for testing purposes, as we require
// injecting our own mocked prober.
func setMapTypesFromProber(prober prober) {
	features := prober.Probe()
	supportedMapTypes = &features.MapTypes
}

// prober abstracts the notion of a kernel feature prober. This is useful for
// testing purposes as it allows us to mock out the kernel, enabling control
// control over what features are returned.
type prober interface {
	// Probe returns the kernel feaures available on machine.
	Probe() probes.Features
}

var commonNameRegexps = []*regexp.Regexp{
	regexp.MustCompile(`^(cilium_)(.+)_reserved_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)_netdev_ns_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)_overlay_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)+$`),
}

func extractCommonName(name string) string {
	for _, r := range commonNameRegexps {
		if replaced := r.ReplaceAllString(name, `$2`); replaced != name {
			return replaced
		}
	}

	return name
}
