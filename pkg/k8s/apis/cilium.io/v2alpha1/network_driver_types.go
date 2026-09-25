// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumNetworkDriverClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CiliumNetworkDriverClusterConfig `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumnetworkdriverclusterconfig",path="ciliumnetworkdriverclusterconfigs",scope="Cluster",shortName={ndcc}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumNetworkDriverClusterConfig is a Kubernetes third-party resource used to
// configure the Cilium Network Driver feature.
type CiliumNetworkDriverClusterConfig struct {
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec CiliumNetworkDriverClusterConfigSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status CiliumNetworkDriverClusterConfigStatus `json:"status,omitempty"`
}

type CiliumNetworkDriverClusterConfigSpec struct {
	// NodeSelector selects a group of nodes where this configuration
	// should be applied
	// If empty / nil this config applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// +kubebuilder:validation:Required
	Spec CiliumNetworkDriverNodeConfigSpec `json:"spec"`
}

type CiliumNetworkDriverClusterConfigStatus struct {
	// The current conditions of the CiliumNetworkDriverClusterConfig
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	// ClusterConfig with conflicting nodeSelector condition
	NetworkDriverClusterConfigConditionConflict = "cilium.io/ConflictingClusterConfiguration"

	// ClusterConfig with conflicting nodeSelector reason
	NetworkDriverClusterConfigReasonConflict = "configurationConflict"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumNetworkDriverNodeConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CiliumNetworkDriverNodeConfig `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumnetworkdrivernodeconfig",path="ciliumnetworkdrivernodeconfigs",scope="Cluster",shortName={ndnc}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumNetworkDriverNodeConfig is a Kubernetes third-party resource used to
// configure the Cilium Network Driver feature.
type CiliumNetworkDriverNodeConfig struct {
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec CiliumNetworkDriverNodeConfigSpec `json:"spec"`
}
type CiliumNetworkDriverNodeConfigSpec struct {
	// Interval between DRA registration retries
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=1
	DraRegistrationRetryIntervalSeconds int64 `json:"draRegistrationRetryInterval,omitempty"`
	// Max amount of time waiting for DRA registration to succeed per attempt.
	// If a single attempt times out the plugin sockets are recreated to retrigger
	// kubelet's plugin-watcher inotify, and a new attempt is started.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=5
	DraRegistrationTimeoutSeconds int64 `json:"draRegistrationTimeout,omitempty"`
	// Maximum number of DRA registration attempts before giving up.
	// Each failed attempt recreates the plugin sockets so that kubelet's
	// inotify-based plugin watcher is retriggered.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=10
	DraRegistrationMaxAttempts int64 `json:"draRegistrationMaxAttempts,omitempty"`

	// Driver name used to register to DRA and with the container runtime.
	// Is also the driver that shows up in the ResourceSlice resources advertised by the node.
	// Format: FQDN
	//
	// +kubebuilder:default=networkdriver.cilium.io
	// +kubebuilder:validation:Optional
	DriverName string `json:"driverName"`

	// Definition of device pools to be advertised by the Network Driver.
	// Pool names must be unique.
	//
	// +kubebuilder:validation:Optional
	Pools []CiliumNetworkDriverDevicePoolConfig `json:"pools,omitempty"`

	// Device manager configurations
	//
	// +kubebuilder:validation:Optional
	DeviceManagerConfigs *CiliumNetworkDriverDeviceManagerConfig `json:"deviceManagerConfigs,omitempty"`
}

// Name for a pool.
type CiliumNetworkDriverPoolName string

// Pool configuration. Devices matched by the filter are advertised
// with the pool name as a ResourceSlice.
//
// +deepequal-gen=true
type CiliumNetworkDriverDevicePoolConfig struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[^/]+$`
	PoolName string `json:"name"`

	// +kubebuilder:validation:Optional
	Filter *CiliumNetworkDriverDeviceFilter `json:"filter"`
}

// Criteria to match devices that are to be advertised as part of a pool.
// All conditions must match for a device to be selected by the filter.
//
// +deepequal-gen=true
type CiliumNetworkDriverDeviceFilter struct {
	// +kubebuilder:validation:Optional
	PFNames []string `json:"pfNames,omitempty"`

	// +kubebuilder:validation:Optional
	PCIAddrs []string `json:"pciAddrs,omitempty"`

	// +kubebuilder:validation:Optional
	VendorIDs []string `json:"vendorIDs,omitempty"`

	// +kubebuilder:validation:Optional
	DeviceIDs []string `json:"deviceIDs,omitempty"`

	// +kubebuilder:validation:Optional
	Drivers []string `json:"drivers,omitempty"`

	// +kubebuilder:validation:Optional
	IfNames []string `json:"ifNames,omitempty"`

	// +kubebuilder:validation:Optional
	DeviceManagers []string `json:"deviceManagers,omitempty"`

	// +kubebuilder:validation:Optional
	ParentIfNames []string `json:"parentIfNames,omitempty"`
}

// +deepequal-gen=true
type CiliumNetworkDriverDeviceManagerConfig struct {
	// Configuration for the SR-IOV device manager
	//
	// +kubebuilder:validation:Optional
	SRIOV *SRIOVDeviceManagerConfig `json:"sriov,omitempty"`

	// Configuration for the eswitch SR-IOV device manager
	//
	// +kubebuilder:validation:Optional
	EswitchSRIOV *EswitchSRIOVDeviceManagerConfig `json:"eswitchSriov,omitempty"`

	// Configuration for the dummy device manager
	//
	// +kubebuilder:validation:Optional
	Dummy *DummyDeviceManagerConfig `json:"dummy,omitempty"`

	// Configuration for the macvlan device manager
	//
	// +kubebuilder:validation:Optional
	Macvlan *MacvlanDeviceManagerConfig `json:"macvlan,omitempty"`
}

// Configuration for the SR-IOV device manager.
//
// +deepequal-gen=true
type SRIOVDeviceManagerConfig struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	SysPCIDevicesPath string `json:"sysBusPCIDevPath,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=ifName
	Ifaces []SRIOVDeviceConfig `json:"ifaces,omitempty"`
}

// Configuration for SR-IOV devices
type SRIOVDeviceConfig struct {
	// Number of VF to be spawned for this PF.
	//
	// +kubebuilder:default=0
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="VFCount is immutable"
	VFCount int `json:"vfCount"`

	// Kernel ifname
	//
	// +kubebuilder:validation:Required
	IfName string `json:"ifName"`
}

// Configuration for the eswitch SR-IOV device manager. Manages PFs whose NIC
// supports switchdev/eswitch offload mode (e.g. Mellanox/NVIDIA ConnectX):
// VFs are represented in the host by a representor netdev, and per-VF
// isolation (VLAN, etc.) is enforced via Linux bridge VLAN filtering on the
// representor rather than ndo_set_vf_vlan, which switchdev-mode NICs
// typically reject for non-zero VLANs.
//
// +deepequal-gen=true
type EswitchSRIOVDeviceManagerConfig struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	SysPCIDevicesPath string `json:"sysBusPCIDevPath,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=ifName
	Ifaces []EswitchSRIOVDeviceConfig `json:"ifaces,omitempty"`

	// Bridges defines the Linux bridges available to be attached to PFs
	// managed by this device manager, keyed by Name. A single bridge may be
	// referenced by BridgeName from multiple EswitchSRIOVDeviceConfig entries,
	// in which case all their PF uplinks and VF representors are attached to
	// the same bridge.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Bridges []EswitchBridgeConfig `json:"bridges,omitempty"`
}

// Configuration for a PF managed by the eswitch SR-IOV device manager.
type EswitchSRIOVDeviceConfig struct {
	// Kernel ifname of the PF.
	//
	// +kubebuilder:validation:Required
	IfName string `json:"ifName"`

	// Number of VFs to be spawned for this PF.
	//
	// +kubebuilder:default=0
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="VFCount is immutable"
	VFCount int `json:"vfCount"`

	// Name of the bridge (from EswitchSRIOVDeviceManagerConfig.Bridges) that
	// this PF's uplink and VF representors are attached to. Required for
	// VLAN isolation to be enforced; if empty, devices on this PF are
	// advertised but VLAN configuration is rejected.
	//
	// +kubebuilder:validation:Optional
	BridgeName string `json:"bridgeName,omitempty"`
}

// Configuration for a Linux bridge managed by the eswitch SR-IOV device
// manager. May be attached to more than one PF's uplink/representors by
// being referenced from multiple EswitchSRIOVDeviceConfig entries.
//
// +deepequal-gen=true
type EswitchBridgeConfig struct {
	// Name of the Linux bridge. If it does not already exist it is created;
	// if it exists, its parameters are reconciled to match Params.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Arbitrary Linux bridge parameters to apply when creating or
	// reconciling the bridge, e.g. "vlan_filtering": "1",
	// "multicast_snooping": "0", "stp_state": "0". Keys correspond to the
	// bridge's sysfs attribute names under
	// /sys/class/net/<bridge>/bridge/, letting any bridge parameter be set
	// without requiring an API change; unrecognized keys are rejected at
	// reconcile time rather than at admission. Values are the string form
	// written to the corresponding sysfs file.
	//
	// +kubebuilder:validation:Optional
	Params map[string]string `json:"params,omitempty"`
}

// Configuration for the dummy device manager.
//
// +deepequal-gen=true
type DummyDeviceManagerConfig struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled,omitempty"`

	// Number of dummy links to create and advertise. The driver synthesises
	// Count discrete devices named dummy0..dummy<Count-1>; each is created on
	// demand when a claim is prepared and destroyed with the pod netns. The
	// (Count+1)th claim stays Pending.
	//
	// +kubebuilder:default=0
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	Count int `json:"count,omitempty"`
}

// Configuration for the macvlan device manager.
//
// +deepequal-gen=true
type MacvlanDeviceManagerConfig struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=parentIfName
	Ifaces []MacvlanDeviceConfig `json:"ifaces,omitempty"`
}

// Configuration for macvlan devices
type MacvlanDeviceConfig struct {
	// Number of macvlan sub-interfaces to create for this parent interface.
	//
	// +kubebuilder:default=0
	// +kubebuilder:validation:Optional
	Count int `json:"count"`

	// Parent interface name (kernel ifname)
	//
	// +kubebuilder:validation:Required
	ParentIfName string `json:"parentIfName"`

	// Macvlan mode (private, vepa, bridge, passthru, source). Defaults to bridge.
	//
	// +kubebuilder:default="bridge"
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=private;vepa;bridge;passthru;source
	Mode string `json:"mode,omitempty"`
}

type IPv4StaticRouteSpec struct {
	// Destination specifies the route destination parameter
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	Destination string `json:"destination"`

	// Gateway specifies the route gateway address
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	Gateway string `json:"gateway"`
}
