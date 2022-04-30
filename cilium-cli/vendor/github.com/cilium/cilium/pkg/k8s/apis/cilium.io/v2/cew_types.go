// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumexternalworkload",path="ciliumexternalworkloads",scope="Cluster",shortName={cew}
// +kubebuilder:printcolumn:JSONPath=".status.id",name="Cilium ID",type=integer
// +kubebuilder:printcolumn:JSONPath=".status.ip",name="IP",type=string
// +kubebuilder:subresource:status

// CiliumExternalWorkload is a Kubernetes Custom Resource that
// contains a specification for an external workload that can join the
// cluster.  The name of the CRD is the FQDN of the external workload,
// and it needs to match the name in the workload registration. The
// labels on the CRD object are the labels that will be used to
// allocate a Cilium Identity for the external workload. If
// 'io.kubernetes.pod.namespace' or 'io.kubernetes.pod.name' labels
// are not explicitly specified, they will be defaulted to 'default'
// and <workload name>, respectively. 'io.cilium.k8s.policy.cluster'
// will always be defined as the name of the current cluster, which
// defaults to "default".
type CiliumExternalWorkload struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired configuration of the external Cilium workload.
	Spec CiliumExternalWorkloadSpec `json:"spec,omitempty"`

	// Status is the most recent status of the external Cilium workload.
	// It is a read-only field.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumExternalWorkloadStatus `json:"status"`
}

// CiliumExternalWorkloadSpec specifies the configurations for redirecting traffic
// within a workload.
//
// +kubebuilder:validation:Type=object
type CiliumExternalWorkloadSpec struct {
	// IPv4AllocCIDR is the range of IPv4 addresses in the CIDR format that the external workload can
	// use to allocate IP addresses for the tunnel device and the health endpoint.
	//
	// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$`
	IPv4AllocCIDR string `json:"ipv4-alloc-cidr,omitempty"`

	// IPv6AllocCIDR is the range of IPv6 addresses in the CIDR format that the external workload can
	// use to allocate IP addresses for the tunnel device and the health endpoint.
	//
	// +kubebuilder:validation:Pattern=`^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`
	IPv6AllocCIDR string `json:"ipv6-alloc-cidr,omitempty"`
}

// CiliumExternalWorkloadStatus is the status of a the external Cilium workload.
type CiliumExternalWorkloadStatus struct {
	// ID is the numeric identity allocated for the external workload.
	ID uint64 `json:"id,omitempty"`

	// IP is the IP address of the workload. Empty if the workload has not registered.
	IP string `json:"ip,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumExternalWorkloadList is a list of CiliumExternalWorkload objects.
type CiliumExternalWorkloadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumExternalWorkload
	Items []CiliumExternalWorkload `json:"items"`
}
