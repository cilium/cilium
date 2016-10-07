//
// Copyright 2016 Authors of Cilium
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
//
package common

var (
	// Version number needs to be var since we override the value when building
	Version = "dev"
)

const (
	// Cilium constants

	// CiliumPath is the path where cilium operational files are running.
	CiliumPath    = "/var/run/cilium"
	DefaultLibDir = "/usr/lib/cilium"
	CiliumUIPath  = DefaultLibDir + "/ui"
	// CiliumSock is the cilium socket for the communication between the daemon and cilium client.
	CiliumSock = CiliumPath + "/cilium.sock"
	// DefaultContainerMAC represents a dummy MAC address for the containers.
	DefaultContainerMAC = "AA:BB:CC:DD:EE:FF"
	// BPFMap is the file that contains the BPF Map for the host.
	BPFMapRoot    = "/sys/fs/bpf"
	BPFCiliumMaps = BPFMapRoot + "/tc/globals"
	BPFMap        = BPFCiliumMaps + "/cilium_lxc"
	// Basename prefix of endpoint specific policy map
	PolicyMapName = "cilium_policy_"
	// Path prefix to endpoint specific policy map
	PolicyMapPath = BPFCiliumMaps + "/" + PolicyMapName
	Ct6MapName    = "cilium_ct6_"
	BPFMapCT6     = BPFCiliumMaps + "/" + Ct6MapName
	Ct4MapName    = "cilium_ct4_"
	BPFMapCT4     = BPFCiliumMaps + "/" + Ct4MapName
	// RFC3339Milli is the RFC3339 with milliseconds for the default timestamp format
	// log files.
	RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

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
	// FirstFreeLabelID is the first ID for which the labels should be assigned.
	FirstFreeLabelID = uint32(256)
	// LastFreeServiceIDKeyPath is the path where the Last free UUID is stored in consul.
	LastFreeServiceIDKeyPath = OperationalPath + "/Services/LastUUID"
	// ServiceKeyPath is the base path where services are stored in consul.
	ServicesKeyPath = OperationalPath + "/Services/SHA256SUMServices"
	// ServiceIDKeyPath is the base path where the IDs are stored in consul.
	ServiceIDKeyPath = OperationalPath + "/Services/IDs"
	// MaxSetOfServiceID is maximum number of set of service IDs that can be stored in consul.
	MaxSetOfServiceID = uint32(0xFFFF)
	// FirstFreeServiceID is the first ID for which the services should be assigned.
	FirstFreeServiceID = uint32(1)

	// Miscellaneous dedicated constants

	// GlobalLabelPrefix is the default root path for the policy.
	GlobalLabelPrefix = "io.cilium"
	// CiliumLabelSource is the default label source for the labels read from containers.
	CiliumLabelSource = "cilium"
	// K8sLabelSource is the default label source for the labels read from kubernetes.
	K8sLabelSource = "k8s"
	// K8sAnnotationName is the annotation name used for the cilium policy name in the
	// kubernetes network policy.
	K8sAnnotationName = "io.cilium.name"
	// K8sPodNamespaceLabel is the label used in kubernetes containers to specify
	// which namespace they belong to.
	K8sPodNamespaceLabel = "io.kubernetes.pod.namespace"
	// K8sAnnotationParentName is the annotation name used for the cilium policy
	// parent name in the kubernetes network policy.
	K8sAnnotationParentName = "io.cilium.parent"
	// Label source for reserved types
	ReservedLabelSource = "reserved"
	// Label used to represent the reserved source
	ReservedLabelKey = GlobalLabelPrefix + "." + ReservedLabelSource
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
	// Name of the header file used for bpf_netdev.c and bpf_overlay.c
	NetdevHeaderFileName = "netdev_config.h"
	// CiliumCHeaderPrefix is the prefix using when printing/writing an endpoint in a
	// base64 form.
	CiliumCHeaderPrefix = "CILIUM_BASE64_"
)
