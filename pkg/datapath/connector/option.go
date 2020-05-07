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

package connector

// Available option for DaemonConfig.Ipvlan.OperationMode
const (
	// OperationModeL3S will respect iptables rules e.g. set up for masquerading
	OperationModeL3S = "L3S"

	// OperationModeL3 will bypass iptables rules on the host
	OperationModeL3 = "L3"
)
