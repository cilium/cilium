// Copyright 2020-2021 Authors of Cilium
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

package callsmap

const (
	// MapName is the prefix of the BPF map.
	MapName = "cilium_calls_"
	// HostMapName and NetdevMapName are name prefixes for the host
	// datapath BPF maps. They must be different but have the same length.
	HostMapName   = MapName + "hostns_"
	NetdevMapName = MapName + "netdev_"
	// CustomCallsMapName is the name prefix for the per-endpoint prog
	// array maps used for loading user-defined eBPF programs.
	CustomCallsMapName = MapName + "custom_"
)
