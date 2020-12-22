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

package v2

import (
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/node/addressing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +kubebuilder:resource:singular="ciliumendpoint",path="ciliumendpoints",scope="Namespaced",shortName={cep,ciliumep}
// +kubebuilder:printcolumn:JSONPath=".status.id",description="Cilium endpoint id",name="Endpoint ID",type=integer
// +kubebuilder:printcolumn:JSONPath=".status.identity.id",description="Cilium identity id",name="Identity ID",type=integer
// +kubebuilder:printcolumn:JSONPath=".status.policy.ingress.enforcing",description="Ingress enforcement in the endpoint",name="Ingress Enforcement",type=boolean
// +kubebuilder:printcolumn:JSONPath=".status.policy.egress.enforcing",description="Egress enforcement in the endpoint",name="Egress Enforcement",type=boolean
// +kubebuilder:printcolumn:JSONPath=".status.visibility-policy-status",description="Status of visibility policy in the endpoint",name="Visibility Policy",type=string
// +kubebuilder:printcolumn:JSONPath=".status.state",description="Endpoint current state",name="Endpoint State",type=string
// +kubebuilder:printcolumn:JSONPath=".status.networking.addressing[0].ipv4",description="Endpoint IPv4 address",name="IPv4",type=string
// +kubebuilder:printcolumn:JSONPath=".status.networking.addressing[0].ipv6",description="Endpoint IPv6 address",name="IPv6",type=string
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumEndpoint is the status of a Cilium policy rule.
type CiliumEndpoint struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Optional
	Status EndpointStatus `json:"status"`
}

// EndpointStatus is the status of a Cilium endpoint.
type EndpointStatus struct {
	// ID is the cilium-agent-local ID of the endpoint.
	ID int64 `json:"id,omitempty"`

	// Controllers is the list of failing controllers for this endpoint.
	Controllers ControllerList `json:"controllers,omitempty"`

	// ExternalIdentifiers is a set of identifiers to identify the endpoint
	// apart from the pod name. This includes container runtime IDs.
	ExternalIdentifiers *models.EndpointIdentifiers `json:"external-identifiers,omitempty"`

	// Health is the overall endpoint & subcomponent health.
	Health *models.EndpointHealth `json:"health,omitempty"`

	// Identity is the security identity associated with the endpoint
	Identity *EndpointIdentity `json:"identity,omitempty"`

	// Log is the list of the last few warning and error log entries
	Log []*models.EndpointStatusChange `json:"log,omitempty"`

	// Networking is the networking properties of the endpoint.
	//
	// +kubebuilder:validation:Optional
	Networking *EndpointNetworking `json:"networking,omitempty"`

	// Encryption is the encryption configuration of the node
	//
	// +kubebuilder:validation:Optional
	Encryption EncryptionSpec `json:"encryption,omitempty"`

	Policy *EndpointPolicy `json:"policy,omitempty"`

	VisibilityPolicyStatus *string `json:"visibility-policy-status,omitempty"`

	// State is the state of the endpoint.
	//
	// +kubebuilder:validation:Enum=creating;waiting-for-identity;not-ready;waiting-to-regenerate;regenerating;restoring;ready;disconnecting;disconnected;invalid
	State string `json:"state,omitempty"`

	NamedPorts models.NamedPorts `json:"named-ports,omitempty"`
}

// EndpointStatusLogEntries is the maximum number of log entries in
// EndpointStatus.Log.
const EndpointStatusLogEntries = 5

// +k8s:deepcopy-gen=false

// ControllerList is a list of ControllerStatus.
type ControllerList []ControllerStatus

// Sort sorts the ControllerList by controller name
func (c ControllerList) Sort() {
	sort.Slice(c, func(i, j int) bool { return c[i].Name < c[j].Name })
}

// ControllerStatus is the status of a failing controller.
type ControllerStatus struct {
	// Name is the name of the controller
	Name string `json:"name,omitempty"`

	// Configuration is the controller configuration
	Configuration *models.ControllerStatusConfiguration `json:"configuration,omitempty"`

	// Status is the status of the controller
	Status ControllerStatusStatus `json:"status,omitempty"`

	// UUID is the UUID of the controller
	UUID string `json:"uuid,omitempty"`
}

// +k8s:deepcopy-gen=false

// ControllerStatusStatus is the detailed status section of a controller.
type ControllerStatusStatus struct {
	ConsecutiveFailureCount int64  `json:"consecutive-failure-count,omitempty"`
	FailureCount            int64  `json:"failure-count,omitempty"`
	LastFailureMsg          string `json:"last-failure-msg,omitempty"`
	LastFailureTimestamp    string `json:"last-failure-timestamp,omitempty"`
	LastSuccessTimestamp    string `json:"last-success-timestamp,omitempty"`
	SuccessCount            int64  `json:"success-count,omitempty"`
}

// EndpointPolicy represents the endpoint's policy by listing all allowed
// ingress and egress identities in combination with L4 port and protocol.
type EndpointPolicy struct {
	Ingress *EndpointPolicyDirection `json:"ingress,omitempty"`
	Egress  *EndpointPolicyDirection `json:"egress,omitempty"`
}

// EndpointPolicyDirection is the list of allowed identities per direction.
type EndpointPolicyDirection struct {
	Enforcing bool                `json:"enforcing"`
	Allowed   AllowedIdentityList `json:"allowed,omitempty"`
	Denied    DenyIdentityList    `json:"denied,omitempty"`
	// Deprecated
	Removing AllowedIdentityList `json:"removing,omitempty"`
	// Deprecated
	Adding AllowedIdentityList `json:"adding,omitempty"`
}

// IdentityTuple specifies a peer by identity, destination port and protocol.
type IdentityTuple struct {
	Identity       uint64            `json:"identity,omitempty"`
	IdentityLabels map[string]string `json:"identity-labels,omitempty"`
	DestPort       uint16            `json:"dest-port,omitempty"`
	Protocol       uint8             `json:"protocol,omitempty"`
}

// +k8s:deepcopy-gen=false

// IdentityList is a list of IdentityTuple.
type IdentityList []IdentityTuple

// Sort sorts a list IdentityList by numeric identity, port and protocol.
func (a IdentityList) Sort() {
	sort.Slice(a, func(i, j int) bool {
		if a[i].Identity < a[j].Identity {
			return true
		} else if a[i].Identity == a[j].Identity {
			if a[i].DestPort < a[j].DestPort {
				return true
			} else if a[i].DestPort == a[j].DestPort {
				return a[i].Protocol < a[j].Protocol
			}
		}
		return false
	})
}

// +k8s:deepcopy-gen=false

// AllowedIdentityList is a list of IdentityTuples that species peers that are
// allowed.
type AllowedIdentityList IdentityList

// Sort sorts a list IdentityList by numeric identity, port and protocol.
func (a AllowedIdentityList) Sort() {
	IdentityList(a).Sort()
}

// +k8s:deepcopy-gen=false

// DenyIdentityList is a list of IdentityTuples that species peers that are
// denied.
type DenyIdentityList IdentityList

// Sort sorts a list IdentityList by numeric identity, port and protocol.
func (d DenyIdentityList) Sort() {
	IdentityList(d).Sort()
}

// EndpointIdentity is the identity information of an endpoint.
type EndpointIdentity struct {
	// ID is the numeric identity of the endpoint
	ID int64 `json:"id,omitempty"`

	// Labels is the list of labels associated with the identity
	Labels []string `json:"labels,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="ciliumidentity",path="ciliumidentities",scope="Cluster",shortName={ciliumid}
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumIdentity is a CRD that represents an identity managed by Cilium.
// It is intended as a backing store for identity allocation, acting as the
// global coordination backend, and can be used in place of a KVStore (such as
// etcd).
// The name of the CRD is the numeric identity and the labels on the CRD object
// are the the kubernetes sourced labels seen by cilium. This is currently the
// only label source possible when running under kubernetes. Non-kubernetes
// labels are filtered but all labels, from all sources, are places in the
// SecurityLabels field. These also include the source and are used to define
// the identity.
// The labels under metav1.ObjectMeta can be used when searching for
// CiliumIdentity instances that include particular labels. This can be done
// with invocations such as:
//   kubectl get ciliumid -l 'foo=bar'
// Each node using a ciliumidentity updates the status field with it's name and
// a timestamp when it first allocates or uses an identity, and periodically
// after that. It deletes its entry when no longer using this identity.
// cilium-operator uses the list of nodes in status to reference count
// users of this identity, and to expire stale usage.
type CiliumIdentity struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// SecurityLabels is the source-of-truth set of labels for this identity.
	SecurityLabels map[string]string `json:"security-labels"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumIdentityList is a list of CiliumIdentity objects.
type CiliumIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumIdentity
	Items []CiliumIdentity `json:"items"`
}

// +k8s:deepcopy-gen=false

// AddressPair is is a par of IPv4 and/or IPv6 address.
type AddressPair struct {
	IPV4 string `json:"ipv4,omitempty"`
	IPV6 string `json:"ipv6,omitempty"`
}

// +k8s:deepcopy-gen=false

// AddressPairList is a list of address pairs.
type AddressPairList []*AddressPair

// Sort sorts an AddressPairList by IPv4 and IPv6 address.
func (a AddressPairList) Sort() {
	sort.Slice(a, func(i, j int) bool {
		if a[i].IPV4 < a[j].IPV4 {
			return true
		} else if a[i].IPV4 == a[j].IPV4 {
			return a[i].IPV6 < a[j].IPV6
		}
		return false
	})
}

// EndpointNetworking is the addressing information of an endpoint.
type EndpointNetworking struct {
	// IP4/6 addresses assigned to this Endpoint
	Addressing AddressPairList `json:"addressing"`

	// NodeIP is the IP of the node the endpoint is running on. The IP must
	// be reachable between nodes.
	NodeIP string `json:"node,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumEndpointList is a list of CiliumEndpoint objects.
type CiliumEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEndpoint
	Items []CiliumEndpoint `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="ciliumnode",path="ciliumnodes",scope="Cluster",shortName={cn,ciliumn}
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// CiliumNode represents a node managed by Cilium. It contains a specification
// to control various node specific configuration aspects and a status section
// to represent the status of the node.
type CiliumNode struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired specification/configuration of the node.
	Spec NodeSpec `json:"spec"`

	// Status defines the realized specification/configuration and status
	// of the node.
	//
	// +kubebuilder:validation:Optional
	Status NodeStatus `json:"status,omitempty"`
}

// NodeAddress is a node address.
type NodeAddress struct {
	// Type is the type of the node address
	Type addressing.AddressType `json:"type,omitempty"`

	// IP is an IP of a node
	IP string `json:"ip,omitempty"`
}

// NodeSpec is the configuration specific to a node.
type NodeSpec struct {
	// InstanceID is the identifier of the node. This is different from the
	// node name which is typically the FQDN of the node. The InstanceID
	// typically refers to the identifier used by the cloud provider or
	// some other means of identification.
	InstanceID string `json:"instance-id,omitempty"`

	// Addresses is the list of all node addresses.
	//
	// +kubebuilder:validation:Optional
	Addresses []NodeAddress `json:"addresses,omitempty"`

	// HealthAddressing is the addressing information for health connectivity
	// checking.
	//
	// +kubebuilder:validation:Optional
	HealthAddressing HealthAddressingSpec `json:"health,omitempty"`

	// Encryption is the encryption configuration of the node.
	//
	// +kubebuilder:validation:Optional
	Encryption EncryptionSpec `json:"encryption,omitempty"`

	// ENI is the AWS ENI specific configuration.
	//
	// +kubebuilder:validation:Optional
	ENI eniTypes.ENISpec `json:"eni,omitempty"`

	// Azure is the Azure IPAM specific configuration.
	//
	// +kubebuilder:validation:Optional
	Azure azureTypes.AzureSpec `json:"azure,omitempty"`

	// IPAM is the address management specification. This section can be
	// populated by a user or it can be automatically populated by an IPAM
	// operator.
	//
	// +kubebuilder:validation:Optional
	IPAM ipamTypes.IPAMSpec `json:"ipam,omitempty"`

	// NodeIdentity is the Cilium numeric identity allocated for the node, if any.
	//
	// +kubebuilder:validation:Optional
	NodeIdentity uint64 `json:"nodeidentity,omitempty"`
}

// HealthAddressingSpec is the addressing information required to do
// connectivity health checking.
type HealthAddressingSpec struct {
	// IPv4 is the IPv4 address of the IPv4 health endpoint.
	//
	// +kubebuilder:validation:Optional
	IPv4 string `json:"ipv4,omitempty"`

	// IPv6 is the IPv6 address of the IPv4 health endpoint.
	//
	// +kubebuilder:validation:Optional
	IPv6 string `json:"ipv6,omitempty"`
}

// EncryptionSpec defines the encryption relevant configuration of a node.
type EncryptionSpec struct {
	// Key is the index to the key to use for encryption or 0 if encryption is
	// disabled.
	//
	// +kubebuilder:validation:Optional
	Key int `json:"key,omitempty"`
}

// NodeStatus is the status of a node.
type NodeStatus struct {
	// ENI is the AWS ENI specific status of the node.
	//
	// +kubebuilder:validation:Optional
	ENI eniTypes.ENIStatus `json:"eni,omitempty"`

	// Azure is the Azure specific status of the node.
	//
	// +kubebuilder:validation:Optional
	Azure azureTypes.AzureStatus `json:"azure,omitempty"`

	// IPAM is the IPAM status of the node.
	//
	// +kubebuilder:validation:Optional
	IPAM ipamTypes.IPAMStatus `json:"ipam,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumNodeList is a list of CiliumNode objects.
type CiliumNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNode
	Items []CiliumNode `json:"items"`
}

// InstanceID returns the InstanceID of a CiliumNode.
func (n *CiliumNode) InstanceID() (instanceID string) {
	if n != nil {
		instanceID = n.Spec.InstanceID
		// OBSOLETE: This fallback can be removed in Cilium 1.9
		if instanceID == "" {
			instanceID = n.Spec.ENI.InstanceID
		}
	}
	return
}
