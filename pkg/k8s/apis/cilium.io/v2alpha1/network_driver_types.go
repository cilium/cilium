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
	// Max amount of time waiting for DRA registration to succeed
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=5
	DraRegistrationTimeoutSeconds int64 `json:"draRegistrationTimeout,omitempty"`
	// How often DRA plugin scans for devices and publishes resourceslices.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=10
	PublishIntervalSeconds int64 `json:"publishInterval,omitempty"`

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
	PfNames []string `json:"pfNames,omitempty"`

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
	SysPciDevicesPath string `json:"sysBusPCIDevPath,omitempty"`

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
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="VfCount is immutable"
	VfCount int `json:"vfCount"`

	// Kernel ifname
	//
	// +kubebuilder:validation:Required
	IfName string `json:"ifName"`
}

// Configuration for the dummy device manager.
//
// +deepequal-gen=true
type DummyDeviceManagerConfig struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled,omitempty"`
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

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumresourcenetworkconfig",path="ciliumresourcenetworkconfigs",scope="Cluster",shortName={crnc}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion

// CiliumResourceNetworkConfig defines the network parameters to configure a network resource
// claimed from a workload.
type CiliumResourceNetworkConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Spec []CiliumResourceNetworkConfigSpec `json:"spec"`
}

type CiliumResourceNetworkConfigSpec struct {
	// NodeSelector selects a group of nodes where this configuration
	// should be applied
	// If empty / nil this config applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// IPPool is the IP pool from which to get addresses
	//
	// +kubebuilder:validation:Optional
	IPPool string `json:"ipPool"`

	// VLAN is the VLAN ID to configure on devices using this network config.
	// A value of 0 means no VLAN is configured.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4094
	VLAN uint16 `json:"vlan,omitempty"`

	// IPv4 specifies the network configuration for allocated IPv4 addresses
	//
	// +kubebuilder:validation:Optional
	IPv4 *IPv4NetworkConfigSpec `json:"ipv4,omitempty"`

	// IPv6 specifies the network configuration for allocated IPv6 addresses
	//
	// +kubebuilder:validation:Optional
	IPv6 *IPv6NetworkConfigSpec `json:"ipv6,omitempty"`
}

type IPv4NetworkConfigSpec struct {
	// Netmask is the network mask associated to the allocated IPv4 addresses
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	// +kubebuilder:validation:ExclusiveMaximum=false
	NetMask uint8 `json:"netMask"`

	// +kubebuilder:validation:Optional
	StaticRoutes []IPv4StaticRouteSpec `json:"staticRoutes,omitempty"`
}

type IPv6NetworkConfigSpec struct {
	// Netmask is the network mask associated to the allocated IPv6 addresses
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=128
	// +kubebuilder:validation:ExclusiveMaximum=false
	NetMask uint8 `json:"netMask"`

	// StaticRoutes lists the routes that are added when configuring the network resource
	//
	// +kubebuilder:validation:Optional
	StaticRoutes []IPv6StaticRouteSpec `json:"staticRoutes,omitempty"`
}

type IPv4StaticRouteSpec struct {
	// Destination specifies the route destination parameter
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	Destination string `json:"destination"`

	// Gateway specifies the route gateway address
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ipv4
	Gateway string `json:"gateway"`
}

type IPv6StaticRouteSpec struct {
	// Destination specifies the route destination parameter
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	Destination string `json:"destination"`

	// Gateway specifies the route gateway address
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ipv6
	Gateway string `json:"gateway"`
}

// CiliumResourceNetworkConfigList is a list of CiliumResourceNetworkConfig objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type CiliumResourceNetworkConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Items []CiliumResourceNetworkConfig `json:"Items"`
}
