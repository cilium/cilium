// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumNetworkDriverConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CiliumNetworkDriverConfig `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumnetworkdriverconfig",path="ciliumnetworkdriverconfigs",scope="Cluster",shortName={ndc}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumNetworkDriverConfig is a Kubernetes third-party resource used to
// configure the Cilium Network Driver feature.
type CiliumNetworkDriverConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec CiliumNetworkDriverConfigSpec `json:"spec"`
}
type CiliumNetworkDriverConfigSpec struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata"`

	// Interval between DRA registration retries
	//
	// +kubebuilder:validation:Optional
	DraRegistrationRetryInterval time.Duration `json:"draRegistrationRetryInterval"`
	// Max amount of time waiting for DRA registration to succeed
	//
	// +kubebuilder:validation:Optional
	DraRegistrationTimeout time.Duration `json:"draRegistrationTimeout"`
	// How often DRA plugin scans for devices and publishes resourceslices.
	//
	// +kubebuilder:validation:Optional
	PublishInterval time.Duration `json:"publishInterval"`

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
	Pools CiliumNetworkDriverDevicePoolConfig `json:"pools"`

	// Device manager configurations
	//
	// +kubebuilder:validation:Optional
	DeviceManagerConfigs CiliumNetworkDriverDeviceManagerConfig `json:"deviceManagerConfigs"`
}

// Name for a pool.
type CiliumNetworkDriverPoolName string

// Pool configuration. Devices matched by the filter are advertised
// with the pool name as a ResourceSlice.
//
// +deepequal-gen=true
type CiliumNetworkDriverDevicePoolConfig map[CiliumNetworkDriverPoolName]CiliumNetworkDriverDeviceFilter

// Criteria to match devices that are to be advertised as part of a pool.
// All conditions must match for a device to be selected by the filter.
//
// +deepequal-gen=true
type CiliumNetworkDriverDeviceFilter struct {
	PfNames        []string `json:"pfNames"`
	PCIAddrs       []string `json:"pciAddrs"`
	VendorIDs      []string `json:"vendorIDs"`
	DeviceIDs      []string `json:"deviceIDs"`
	Drivers        []string `json:"drivers"`
	IfNames        []string `json:"ifNames"`
	DeviceManagers []string `json:"deviceManagers"`
}

type CiliumNetworkDriverDeviceManagerConfig struct {
	SRIOV SRIOVDeviceManagerConfig `json:"sriov"`
}

// Configuration for the SR-IOV device manager.
type SRIOVDeviceManagerConfig struct {
	Enabled bool                         `json:"enabled"`
	Ifaces  map[string]SRIOVDeviceConfig `json:"ifaces"`
}

// Configuration for SR-IOV devices
type SRIOVDeviceConfig struct {
	// Number of VF to be spawned for this PF.
	VfCount int `json:"vfCount"`
}
