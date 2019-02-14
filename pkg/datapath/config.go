// Copyright 2019 Authors of Cilium
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

package datapath

import (
	"github.com/cilium/cilium/pkg/option"
)

// DeviceConfiguration is an interface for injecting configuration of datapath
// options that affect lookups and logic applied at a per-device level, whether
// those are devices associated with the endpoint or associated with the host.
type DeviceConfiguration interface {
	// GetCIDRPrefixLengths fetches the lists of unique IPv6 and IPv4
	// prefix lengths used for datapath lookups, each of which is sorted
	// from longest prefix to shortest prefix. It must return more than
	// one element in each returned array.
	GetCIDRPrefixLengths() (s6, s4 []int)

	// GetOptions fetches the configurable datapath options from the owner.
	GetOptions() *option.IntOptions
}
