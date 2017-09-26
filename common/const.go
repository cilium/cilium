// Copyright 2016-2017 Authors of Cilium
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

	// LastFreeLabelIDKeyPath is the path where the Last free UUID is stored in the kvstore.
	LastFreeLabelIDKeyPath = OperationalPath + "/Labels/LastUUID"
	// LabelsKeyPath is the base path where labels are stored in the kvstore.
	LabelsKeyPath = OperationalPath + "/Labels/SHA256SUMLabels"
	// LabelIDKeyPath is the base path where the IDs are stored in the kvstore.
	LabelIDKeyPath = OperationalPath + "/Labels/IDs"
	// MaxSetOfLabels is maximum number of set of labels that can be stored in the kvstore.
	MaxSetOfLabels = uint32(0xFFFF)
	// LastFreeServiceIDKeyPath is the path where the Last free UUID is stored in the kvstore.
	LastFreeServiceIDKeyPath = OperationalPath + "/ServicesV2/LastUUID"
	// ServicesKeyPath is the base path where services are stored in the kvstore.
	ServicesKeyPath = OperationalPath + "/ServicesV2/SHA256SUMServices"
	// ServiceIDKeyPath is the base path where the IDs are stored in the kvstore.
	ServiceIDKeyPath = OperationalPath + "/ServicesV2/IDs"
	// ServicePathV1 is the base path for the services stored in the kvstore.
	ServicePathV1 = OperationalPath + "/Services/"
	// MaxSetOfServiceID is maximum number of set of service IDs that can be stored in the kvstore.
	MaxSetOfServiceID = uint32(0xFFFF)
	// FirstFreeServiceID is the first ID for which the services should be assigned.
	FirstFreeServiceID = uint32(1)

	// Miscellaneous dedicated constants

	// PathDelimiter is the delimiter used in the labels paths.
	PathDelimiter = "."

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

	// CiliumK8sAnnotationPrefix is the prefix key for the annotations used in kubernetes.
	CiliumK8sAnnotationPrefix = "cilium.io/"

	// CiliumIdentityAnnotation is the annotation key used to map to an endpoint's security identity.
	CiliumIdentityAnnotation = CiliumK8sAnnotationPrefix + "identity"
	// CiliumIdentityAnnotationDeprecated is the previous annotation key used to map to an endpoint's security identity.
	CiliumIdentityAnnotationDeprecated = "cilium-identity"
)
