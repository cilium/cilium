// Copyright 2021 Authors of Cilium
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

package recorder

const (
	// MapNameWcard4 represents IPv4 capture wildcard table.
	MapNameWcard4 = "cilium_capture4_rules"
	// MapNameWcard6 represents IPv6 capture wildcard table.
	MapNameWcard6 = "cilium_capture6_rules"
	// MapSize is the default size of the v4 and v6 maps
	MapSize = 16384
)

type CaptureRule struct {
	RuleId   uint16 `align:"rule_id"`
	Reserved uint16 `align:"reserved"`
	CapLen   uint32 `align:"cap_len"`
}
