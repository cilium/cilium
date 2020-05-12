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
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/comparator"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/go-openapi/swag"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumNetworkPolicy is a Kubernetes third-party resource with an extended version
// of NetworkPolicy
// +deepequal-gen:private-method=true
type CiliumNetworkPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec *api.Rule `json:"spec,omitempty"`

	// Specs is a list of desired Cilium specific rule specification.
	Specs api.Rules `json:"specs,omitempty"`

	// Status is the status of the Cilium policy rule
	// +optional
	Status CiliumNetworkPolicyStatus `json:"status"`
}

func (in *CiliumNetworkPolicy) DeepEqual(other *CiliumNetworkPolicy) bool {
	switch {
	case (in == nil) != (other == nil):
		return false
	case (in == nil) && (other == nil):
		return true
	}

	if !(in.Name == other.Name && in.Namespace == other.Namespace) {
		return false
	}

	// Ignore v1.LastAppliedConfigAnnotation annotation
	lastAppliedCfgAnnotation1, ok1 := in.GetAnnotations()[v1.LastAppliedConfigAnnotation]
	lastAppliedCfgAnnotation2, ok2 := other.GetAnnotations()[v1.LastAppliedConfigAnnotation]
	defer func() {
		if ok1 && in.GetAnnotations() != nil {
			in.GetAnnotations()[v1.LastAppliedConfigAnnotation] = lastAppliedCfgAnnotation1
		}
		if ok2 && other.GetAnnotations() != nil {
			other.GetAnnotations()[v1.LastAppliedConfigAnnotation] = lastAppliedCfgAnnotation2
		}
	}()
	delete(in.GetAnnotations(), v1.LastAppliedConfigAnnotation)
	delete(other.GetAnnotations(), v1.LastAppliedConfigAnnotation)

	return comparator.MapStringEquals(in.GetAnnotations(), other.GetAnnotations()) &&
		in.deepEqual(other)
}

// CiliumNetworkPolicyStatus is the status of a Cilium policy rule
// +deepequal-gen=true
type CiliumNetworkPolicyStatus struct {
	// Nodes is the Cilium policy status for each node
	Nodes map[string]CiliumNetworkPolicyNodeStatus `json:"nodes,omitempty"`

	// DerivativePolicies is the status of all policies derived from the Cilium
	// policy
	DerivativePolicies map[string]CiliumNetworkPolicyNodeStatus `json:"derivativePolicies,omitempty"`
}

// CiliumNetworkPolicyNodeStatus is the status of a Cilium policy rule for a
// specific node
// +deepequal-gen=true
type CiliumNetworkPolicyNodeStatus struct {
	// OK is true when the policy has been parsed and imported successfully
	// into the in-memory policy repository on the node.
	OK bool `json:"ok,omitempty"`

	// Error describes any error that occurred when parsing or importing the
	// policy, or realizing the policy for the endpoints to which it applies
	// on the node.
	Error string `json:"error,omitempty"`

	// LastUpdated contains the last time this status was updated
	LastUpdated Timestamp `json:"lastUpdated,omitempty"`

	// Revision is the policy revision of the repository which first implemented
	// this policy.
	Revision uint64 `json:"localPolicyRevision,omitempty"`

	// Enforcing is set to true once all endpoints present at the time the
	// policy has been imported are enforcing this policy.
	Enforcing bool `json:"enforcing,omitempty"`

	// Annotations corresponds to the Annotations in the ObjectMeta of the CNP
	// that have been realized on the node for CNP. That is, if a CNP has been
	// imported and has been assigned annotation X=Y by the user,
	// Annotations in CiliumNetworkPolicyNodeStatus will be X=Y once the
	// CNP that was imported corresponding to Annotation X=Y has been realized on
	// the node.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CreateCNPNodeStatus returns a CiliumNetworkPolicyNodeStatus created from the
// provided fields
func CreateCNPNodeStatus(enforcing, ok bool, cnpError error, rev uint64, annotations map[string]string) CiliumNetworkPolicyNodeStatus {
	cnpns := CiliumNetworkPolicyNodeStatus{
		Enforcing:   enforcing,
		Revision:    rev,
		OK:          ok,
		LastUpdated: NewTimestamp(),
		Annotations: annotations,
	}
	if cnpError != nil {
		cnpns.Error = cnpError.Error()
	}
	return cnpns
}

// NewTimestamp creates a new Timestamp with the current time.Now()
func NewTimestamp() Timestamp {
	return Timestamp{time.Now()}
}

// Timestamp is a wrapper of time.Time so that we can create our own
// implementation of DeepCopyInto.
// +deepequal-gen=false
type Timestamp struct {
	time.Time
}

func (in *Timestamp) DeepEqual(other *Timestamp) bool {
	switch {
	case (in == nil) != (other == nil):
		return false
	case (in == nil) && (other == nil):
		return true
	}
	return in.Time.Equal(other.Time)
}

// DeepCopyInto creates a deep-copy of the Time value.  The underlying time.Time
// type is effectively immutable in the time API, so it is safe to
// copy-by-assign, despite the presence of (unexported) Pointer fields.
func (t *Timestamp) DeepCopyInto(out *Timestamp) {
	*out = *t
}

func (r *CiliumNetworkPolicy) String() string {
	result := ""
	result += fmt.Sprintf("TypeMeta: %s, ", r.TypeMeta.String())
	result += fmt.Sprintf("ObjectMeta: %s, ", r.ObjectMeta.String())
	if r.Spec != nil {
		result += fmt.Sprintf("Spec: %v", *(r.Spec))
	}
	if r.Specs != nil {
		result += fmt.Sprintf("Specs: %v", r.Specs)
	}
	result += fmt.Sprintf("Status: %v", r.Status)
	return result
}

// GetPolicyStatus returns the CiliumNetworkPolicyNodeStatus corresponding to
// nodeName in the provided CiliumNetworkPolicy. If Nodes within the rule's
// Status is nil, returns an empty CiliumNetworkPolicyNodeStatus.
func (r *CiliumNetworkPolicy) GetPolicyStatus(nodeName string) CiliumNetworkPolicyNodeStatus {
	if r.Status.Nodes == nil {
		return CiliumNetworkPolicyNodeStatus{}
	}
	return r.Status.Nodes[nodeName]
}

// SetPolicyStatus sets the given policy status for the given nodes' map
func (r *CiliumNetworkPolicy) SetPolicyStatus(nodeName string, cnpns CiliumNetworkPolicyNodeStatus) {
	if r.Status.Nodes == nil {
		r.Status.Nodes = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.Nodes[nodeName] = cnpns
}

// SetDerivedPolicyStatus set the derivative policy status for the given
// derivative policy name.
func (r *CiliumNetworkPolicy) SetDerivedPolicyStatus(derivativePolicyName string, status CiliumNetworkPolicyNodeStatus) {
	if r.Status.DerivativePolicies == nil {
		r.Status.DerivativePolicies = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.DerivativePolicies[derivativePolicyName] = status
}

// AnnotationsEquals returns true if ObjectMeta.Annotations of each
// CiliumNetworkPolicy are equivalent (i.e., they contain equivalent key-value
// pairs).
func (r *CiliumNetworkPolicy) AnnotationsEquals(o *CiliumNetworkPolicy) bool {
	if o == nil {
		return r == nil
	}
	return reflect.DeepEqual(r.ObjectMeta.Annotations, o.ObjectMeta.Annotations)
}

// Parse parses a CiliumNetworkPolicy and returns a list of cilium policy
// rules.
func (r *CiliumNetworkPolicy) Parse() (api.Rules, error) {
	if r.ObjectMeta.Name == "" {
		return nil, fmt.Errorf("CiliumNetworkPolicy must have name")
	}

	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	retRules := api.Rules{}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, fmt.Errorf("Invalid CiliumNetworkPolicy spec: %s", err)

		}
		cr := k8sCiliumUtils.ParseToCiliumRule(namespace, name, uid, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, fmt.Errorf("Invalid CiliumNetworkPolicy specs: %s", err)

			}
			cr := k8sCiliumUtils.ParseToCiliumRule(namespace, name, uid, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}

// GetControllerName returns the unique name for the controller manager.
func (r *CiliumNetworkPolicy) GetControllerName() string {
	name := k8sUtils.GetObjNamespaceName(&r.ObjectMeta)
	return fmt.Sprintf("%s (v2 %s)", k8sConst.CtrlPrefixPolicyStatus, name)
}

// GetIdentityLabels returns all rule labels in the CiliumNetworkPolicy.
func (r *CiliumNetworkPolicy) GetIdentityLabels() labels.LabelArray {
	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	// Even though the struct represents CiliumNetworkPolicy, we use it both for
	// CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy, so here we check for namespace
	// to send correct derivedFrom label to get the correct policy labels.
	derivedFrom := k8sCiliumUtils.ResourceTypeCiliumNetworkPolicy
	if namespace == "" {
		derivedFrom = k8sCiliumUtils.ResourceTypeCiliumClusterwideNetworkPolicy
	}
	return k8sCiliumUtils.GetPolicyLabels(namespace, name, uid, derivedFrom)
}

// RequiresDerivative return true if the CNP has any rule that will create a new
// derivative rule.
func (r *CiliumNetworkPolicy) RequiresDerivative() bool {
	if r.Spec != nil {
		if r.Spec.RequiresDerivative() {
			return true
		}
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if rule.RequiresDerivative() {
				return true
			}
		}
	}
	return false
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumNetworkPolicyList is a list of CiliumNetworkPolicy objects
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNetworkPolicy
	Items []CiliumNetworkPolicy `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumClusterwideNetworkPolicy is a Kubernetes third-party resource with an modified version
// of CiliumNetworkPolicy which is cluster scoped rather than namespace scoped.
// +deepequal-gen=false
type CiliumClusterwideNetworkPolicy struct {
	*CiliumNetworkPolicy

	// Status is the status of the Cilium policy rule
	// +optional
	// The reason this field exists in this structure is due a bug in the k8s code-generator
	// that doesn't create a `UpdateStatus` method because the field does not exist in
	// the structure.
	Status CiliumNetworkPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumClusterwideNetworkPolicyList is a list of CiliumClusterwideNetworkPolicy objects
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumClusterwideNetworkPolicy
	Items []CiliumClusterwideNetworkPolicy `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumEndpoint is the status of a Cilium policy rule
// +k8s:openapi-gen=false
type CiliumEndpoint struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Status EndpointStatus `json:"status"`
}

// EndpointStatus is the status of a Cilium endpoint
// The custom deepcopy function below is a workaround. We can generate a
// deepcopy for EndpointStatus but not for the various models.* types it
// includes. We can't generate functions for classes in other packages, nor can
// we change the models.Endpoint type to use proxy types we define here.
// +k8s:deepcopy-gen=false
type EndpointStatus struct {
	// The cilium-agent-local ID of the endpoint
	ID int64 `json:"id,omitempty"`

	// Controllers is the list of failing controllers for this endpoint
	Controllers ControllerList `json:"controllers,omitempty"`

	// ExternalIdentifiers is a set of identifiers to identify the endpoint
	// apart from the pod name. This includes container runtime IDs.
	ExternalIdentifiers *models.EndpointIdentifiers `json:"external-identifiers,omitempty"`

	// Summary overall endpoint & subcomponent health
	Health *models.EndpointHealth `json:"health,omitempty"`

	// Identity is the security identity associated with the endpoint
	Identity *EndpointIdentity `json:"identity,omitempty"`

	// Log is the list of the last few warning and error log entries
	Log []*models.EndpointStatusChange `json:"log,omitempty"`

	// Networking properties of the endpoint
	//
	// +optional
	Networking *EndpointNetworking `json:"networking,omitempty"`

	// Encryption is the encryption configuration of the node
	//
	// +optional
	Encryption EncryptionSpec `json:"encryption,omitempty"`

	Policy *EndpointPolicy `json:"policy,omitempty"`

	VisibilityPolicyStatus *string `json:"visibility-policy-status,omitempty"`

	// State is the state of the endpoint
	//
	// States are:
	// - creating
	// - waiting-for-identity
	// - not-ready
	// - waiting-to-regenerate
	// - regenerating
	// - restoring
	// - ready
	// - disconnecting
	// - disconnected
	State string `json:"state,omitempty"`

	NamedPorts models.NamedPorts `json:"named-ports,omitempty"`
}

// EndpointStatusLogEntries is the maximum number of log entries in EndpointStatus.Log
const EndpointStatusLogEntries = 5

// ControllerList is a list of ControllerStatus
// +k8s:deepcopy-gen=false
type ControllerList []ControllerStatus

// Sort sorts the ControllerList by controller name
func (c ControllerList) Sort() {
	sort.Slice(c, func(i, j int) bool { return c[i].Name < c[j].Name })
}

// ControllerStatus is the status of a failing controller
// +k8s:deepcopy-gen=false
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

// ControllerStatusStatus is the detailed status section of a controller
// +k8s:deepcopy-gen=false
type ControllerStatusStatus struct {
	ConsecutiveFailureCount int64  `json:"consecutive-failure-count,omitempty"`
	FailureCount            int64  `json:"failure-count,omitempty"`
	LastFailureMsg          string `json:"last-failure-msg,omitempty"`
	LastFailureTimestamp    string `json:"last-failure-timestamp,omitempty"`
	LastSuccessTimestamp    string `json:"last-success-timestamp,omitempty"`
	SuccessCount            int64  `json:"success-count,omitempty"`
}

// EndpointPolicy represents the endpoint's policy by listing all allowed
// ingress and egress identities in combination with L4 port and protocol
// +k8s:deepcopy-gen=false
type EndpointPolicy struct {
	Ingress *EndpointPolicyDirection `json:"ingress,omitempty"`
	Egress  *EndpointPolicyDirection `json:"egress,omitempty"`
}

// EndpointPolicyDirection is the list of allowed identities per direction
// +k8s:deepcopy-gen=false
type EndpointPolicyDirection struct {
	Enforcing bool                `json:"enforcing"`
	Allowed   AllowedIdentityList `json:"allowed,omitempty"`
	Removing  AllowedIdentityList `json:"removing,omitempty"`
	Adding    AllowedIdentityList `json:"adding,omitempty"`
}

// AllowedIdentityTuple specifies an allowed peer by identity, destination port
// and protocol
// +k8s:deepcopy-gen=false
type AllowedIdentityTuple struct {
	Identity       uint64            `json:"identity,omitempty"`
	IdentityLabels map[string]string `json:"identity-labels,omitempty"`
	DestPort       uint16            `json:"dest-port,omitempty"`
	Protocol       uint8             `json:"protocol,omitempty"`
}

// AllowedIdentityList is a list of AllowedIdentityTuple
// +k8s:deepcopy-gen=false
type AllowedIdentityList []AllowedIdentityTuple

// Sort sorts a list AllowedIdentityTuple by numeric identity, port and protocol
func (a AllowedIdentityList) Sort() {
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

// EndpointIdentity is the identity information of an endpoint
type EndpointIdentity struct {
	// ID is the numeric identity of the endpoint
	ID int64 `json:"id,omitempty"`

	// Labels is the list of labels associated with the identity
	Labels []string `json:"labels,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

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
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// SecurityLabels is the source-of-truth set of labels for this identity.
	SecurityLabels map[string]string `json:"security-labels"`

	// Status is deprecated and no longer used, it will be removed in Cilium 1.9
	// +deepequal-gen=false
	Status IdentityStatus `json:"status"`
}

// IdentityStatus is the status of an identity
//
// This structure is deprecated, do not use.
// +deepequal-gen=false
type IdentityStatus struct {
	Nodes map[string]metav1.Time `json:"nodes,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//
// CiliumIdentityList is a list of CiliumIdentity objects
// +deepequal-gen=false
type CiliumIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumIdentity
	Items []CiliumIdentity `json:"items"`
}

// AddressPair is is a par of IPv4 and/or IPv6 address
// +k8s:deepcopy-gen=false
type AddressPair struct {
	IPV4 string `json:"ipv4,omitempty"`
	IPV6 string `json:"ipv6,omitempty"`
}

// AddressPairList is a list of address pairs
// +k8s:deepcopy-gen=false
type AddressPairList []*AddressPair

// Sort sorts an AddressPairList by IPv4 and IPv6 address
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

// EndpointNetworking is the addressing information of an endpoint
type EndpointNetworking struct {
	// IP4/6 addresses assigned to this Endpoint
	Addressing AddressPairList `json:"addressing"`

	// NodeIP is the IP of the node the endpoint is running on. The IP must
	// be reachable between nodes.
	NodeIP string `json:"node,omitempty"`
}

// DeepCopyInto is an inefficient hack to allow reusing models.Endpoint in the
// CiliumEndpoint CRD.
func (m *EndpointStatus) DeepCopyInto(out *EndpointStatus) {
	*out = *m
	b, err := (*EndpointStatus)(m).MarshalBinary()
	if err != nil {
		log.WithError(err).Error("Cannot marshal EndpointStatus during EndpointStatus deepcopy")
		return
	}
	err = (*EndpointStatus)(out).UnmarshalBinary(b)
	if err != nil {
		log.WithError(err).Error("Cannot unmarshal EndpointStatus during EndpointStatus deepcopy")
		return
	}
}

// MarshalBinary interface implementation
func (m *EndpointStatus) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EndpointStatus) UnmarshalBinary(b []byte) error {
	var res EndpointStatus
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumEndpointList is a list of CiliumEndpoint objects
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEndpoint
	Items []CiliumEndpoint `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumNode represents a node managed by Cilium. It contains a specification
// to control various node specific configuration aspects and a status section
// to represent the status of the node
type CiliumNode struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired specification/configuration of the node
	Spec NodeSpec `json:"spec"`

	// Status defines the realized specification/configuration and status
	// of the node
	Status NodeStatus `json:"status"`
}

// NodeAddress is a node address
type NodeAddress struct {
	// Type is the type of the node address
	Type addressing.AddressType `json:"type,omitempty"`

	// IP is an IP of a node
	IP string `json:"ip,omitempty"`
}

// NodeSpec is the configuration specific to a node
type NodeSpec struct {
	// InstanceID is the identifier of the node. This is different from the
	// node name which is typically the FQDN of the node. The InstanceID
	// typically refers to the identifier used by the cloud provider or
	// some other means of identification.
	InstanceID string `json:"instance-id,omitempty"`

	// Addresses is the list of all node addresses
	//
	// +optional
	Addresses []NodeAddress `json:"addresses,omitempty"`

	// HealthAddressing is the addressing information for health
	// connectivity checking
	//
	// +optional
	HealthAddressing HealthAddressingSpec `json:"health,omitempty"`

	// Encryption is the encryption configuration of the node
	//
	// +optional
	Encryption EncryptionSpec `json:"encryption,omitempty"`

	// ENI is the AWS ENI specific configuration
	//
	// +optional
	ENI eniTypes.ENISpec `json:"eni,omitempty"`

	// Azure is the Azure IPAM specific configuration
	//
	// +optional
	Azure azureTypes.AzureSpec `json:"azure,omitempty"`

	// IPAM is the address management specification. This section can be
	// populated by a user or it can be automatically populated by an IPAM
	// operator
	//
	// +optional
	IPAM ipamTypes.IPAMSpec `json:"ipam,omitempty"`
}

// HealthAddressingSpec is the addressing information required to do
// connectivity health checking
type HealthAddressingSpec struct {
	// IPv4 is the IPv4 address of the IPv4 health endpoint
	//
	// +optional
	IPv4 string `json:"ipv4,omitempty"`

	// IPv6 is the IPv6 address of the IPv4 health endpoint
	//
	// +optional
	IPv6 string `json:"ipv6,omitempty"`
}

// EncryptionSpec defines the encryption relevant configuration of a node
type EncryptionSpec struct {
	// Key is the index to the key to use for encryption or 0 if encryption
	// is disabled
	//
	// +optional
	Key int `json:"key,omitempty"`
}

// NodeStatus is the status of a node
type NodeStatus struct {
	// ENI is the AWS ENI specific status of the node
	//
	// +optional
	ENI eniTypes.ENIStatus `json:"eni,omitempty"`

	// Azure is the Azure specific status of the node
	//
	// +optional
	Azure azureTypes.AzureStatus `json:"azure,omitempty"`

	// IPAM is the IPAM status of the node
	//
	// +optional
	IPAM ipamTypes.IPAMStatus `json:"ipam,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//
// CiliumNodeList is a list of CiliumNode objects
// +deepequal-gen=false
type CiliumNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNode
	Items []CiliumNode `json:"items"`
}

// InstanceID returns the InstanceID of a CiliumNode
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
