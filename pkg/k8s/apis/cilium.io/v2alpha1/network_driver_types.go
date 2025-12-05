// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	"github.com/cilium/cilium/pkg/time"

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
	// +kubebuilder:validation:Optional
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec CiliumNetworkDriverConfigSpec `json:"spec"`
}
type CiliumNetworkDriverConfigSpec struct {
	// Interval between DRA registration retries
	//
	// +kubebuilder:validation:Optional
	DraRegistrationRetryInterval *time.Duration `json:"draRegistrationRetryInterval,omitempty"`
	// Max amount of time waiting for DRA registration to succeed
	//
	// +kubebuilder:validation:Optional
	DraRegistrationTimeout *time.Duration `json:"draRegistrationTimeout,omitempty"`
	// How often DRA plugin scans for devices and publishes resourceslices.
	//
	// +kubebuilder:validation:Optional
	PublishInterval *time.Duration `json:"publishInterval,omitempty"`

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
	Pools *CiliumNetworkDriverDevicePoolConfig `json:"pools,omitempty"`

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
type CiliumNetworkDriverDevicePoolConfig map[CiliumNetworkDriverPoolName]CiliumNetworkDriverDeviceFilter

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
}

// Configuration for the SR-IOV device manager.
//
// +deepequal-gen=true
type SRIOVDeviceManagerConfig struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	Ifaces map[string]SRIOVDeviceConfig `json:"ifaces,omitempty"`
}

// Configuration for SR-IOV devices
type SRIOVDeviceConfig struct {
	// Number of VF to be spawned for this PF.
	//
	// +kubebuilder:default=0
	// +kubebuilder:validation:Optional
	VfCount int `json:"vfCount"`
}

// Configuration for the dummy device manager.
//
// +deepequal-gen=true
type DummyDeviceManagerConfig struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled,omitempty"`
}
