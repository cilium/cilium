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

	// OperationalPath is the base path to store the operational details in consul.
	OperationalPath = "cilium-net/operational"

	// LastFreeLabelIDKeyPath is the path where the Last free UUID is stored in consul.
	LastFreeLabelIDKeyPath = OperationalPath + "/Labels/LastUUID"
	// LabelsKeyPath is the base path where labels are stored in consul.
	LabelsKeyPath = OperationalPath + "/Labels/SHA256SUMLabels"
	// LabelIDKeyPath is the base path where the IDs are stored in consul.
	LabelIDKeyPath = OperationalPath + "/Labels/IDs"
	// MaxSetOfLabels is maximum number of set of labels that can be stored in consul.
	MaxSetOfLabels = uint32(0xFFFF)
	// LastFreeServiceIDKeyPath is the path where the Last free UUID is stored in consul.
	LastFreeServiceIDKeyPath = OperationalPath + "/Services/LastUUID"
	// ServicesKeyPath is the base path where services are stored in consul.
	ServicesKeyPath = OperationalPath + "/Services/SHA256SUMServices"
	// ServiceIDKeyPath is the base path where the IDs are stored in consul.
	ServiceIDKeyPath = OperationalPath + "/Services/IDs"
	// MaxSetOfServiceID is maximum number of set of service IDs that can be stored in consul.
	MaxSetOfServiceID = uint32(0xFFFF)
	// FirstFreeServiceID is the first ID for which the services should be assigned.
	FirstFreeServiceID = uint32(1)

	// Miscellaneous dedicated constants

	// CiliumLabelSource is the default label source for the labels read from containers.
	CiliumLabelSource = "cilium"
	// K8sLabelSource is the default label source for the labels read from kubernetes.
	K8sLabelSource = "k8s"
	// K8sAnnotationName is the annotation name used for the cilium policy name in the
	// kubernetes network policy.
	K8sAnnotationName = "io.cilium.name"
	// K8sLabelPrefix is the default prefix used to represent kubernetes labels
	K8sLabelPrefix = "io.cilium.k8s."
	// K8sDefaultParent is the default prefix for network policies received from
	// kubernetes.
	K8sDefaultParent = "io.cilium.k8s"
	// K8sPodNamespaceLabel is the label used in kubernetes containers to specify
	// which namespace they belong to.
	K8sPodNamespaceLabel = "io.kubernetes.pod.namespace"
	// K8sAnnotationParentName is the annotation name used for the cilium policy
	// parent name in the kubernetes network policy.
	K8sAnnotationParentName = "io.cilium.parent"
	// K8sEnvNodeNameSpec is the environment variable label.
	K8sEnvNodeNameSpec = "K8S_NODE_NAME"
	// ReservedLabelSource is the label source for reserved types.
	ReservedLabelSource = "reserved"
	// ReservedLabelKey is the label used to represent the reserved source.
	ReservedLabelKey = "io.cilium." + ReservedLabelSource
	// EndpointsPerHost is the maximum number of endpoints allowed per host. It should
	// represent the same number of IPv6 addresses supported on each node.
	EndpointsPerHost = 0xFFFF
	// GroupFilePath is the unix group file path.
	GroupFilePath = "/etc/group"
	// CiliumGroupName is the cilium's unix group name.
	CiliumGroupName = "cilium"

	// CHeaderFileName is the name of the C header file for BPF programs for a
	// particular endpoint.
	CHeaderFileName = "lxc_config.h"
	// NetdevHeaderFileName is the name of the header file used for bpf_netdev.c and bpf_overlay.c.
	NetdevHeaderFileName = "netdev_config.h"
	// CiliumCHeaderPrefix is the prefix using when printing/writing an endpoint in a
	// base64 form.
	CiliumCHeaderPrefix = "CILIUM_BASE64_"
)
