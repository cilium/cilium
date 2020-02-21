// Copyright 2016-2020 Authors of Cilium
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

package common

const (
	// Consul dedicated constants

	// OperationalPath is the base path to store the operational details in the kvstore.
	OperationalPath = "cilium-net/operational"

	// ServicesKeyPath is the base path where services are stored in the kvstore.
	ServicesKeyPath = OperationalPath + "/ServicesV2/SHA256SUMServices"
	// ServicePathV1 is the base path for the services stored in the kvstore.
	ServicePathV1 = OperationalPath + "/Services/"

	// Miscellaneous dedicated constants

	// NodeConfigFile is the name of the C header which contains the node's
	// network parameters.
	NodeConfigFile = "node_config.h"
	// CHeaderFileName is the name of the C header file for BPF programs for a
	// particular endpoint.
	CHeaderFileName = "lxc_config.h"
	// NetdevHeaderFileName is the name of the header file used for bpf_netdev.c and bpf_overlay.c.
	NetdevHeaderFileName = "netdev_config.h"
	// PreFilterHeaderFileName is the name of the header file used for bpf_xdp.c.
	PreFilterHeaderFileName = "filter_config.h"
	// CiliumCHeaderPrefix is the prefix using when printing/writing an endpoint in a
	// base64 form.
	CiliumCHeaderPrefix = "CILIUM_BASE64_"

	// PossibleCPUSysfsPath is used to retrieve the number of CPUs for per-CPU maps.
	PossibleCPUSysfsPath = "/sys/devices/system/cpu/possible"
)
