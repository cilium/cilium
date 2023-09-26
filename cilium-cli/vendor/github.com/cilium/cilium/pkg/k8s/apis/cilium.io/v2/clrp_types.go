// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/iana"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumlocalredirectpolicy",path="ciliumlocalredirectpolicies",scope="Namespaced",shortName={clrp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// CiliumLocalRedirectPolicy is a Kubernetes Custom Resource that contains a
// specification to redirect traffic locally within a node.
type CiliumLocalRedirectPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired behavior of the local redirect policy.
	Spec CiliumLocalRedirectPolicySpec `json:"spec,omitempty"`

	// Status is the most recent status of the local redirect policy.
	// It is a read-only field.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumLocalRedirectPolicyStatus `json:"status"`
}

type Frontend struct {
	// IP is a destination ip address for traffic to be redirected.
	//
	// Example:
	// When it is set to "169.254.169.254", traffic destined to
	// "169.254.169.254" is redirected.
	//
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	// +kubebuilder:validation:Required
	IP string `json:"ip"`

	// ToPorts is a list of destination L4 ports with protocol for traffic
	// to be redirected.
	// When multiple ports are specified, the ports must be named.
	//
	// Example:
	// When set to Port: "53" and Protocol: UDP, traffic destined to port '53'
	// with UDP protocol is redirected.
	//
	// +kubebuilder:validation:Required
	ToPorts []PortInfo `json:"toPorts"`
}

// RedirectFrontend is a frontend configuration that matches traffic that needs to be redirected.
// The configuration must be specified using a ip/port tuple or a Kubernetes service.
type RedirectFrontend struct {
	// AddressMatcher is a tuple {IP, port, protocol} that matches traffic to be
	// redirected.
	//
	// +kubebuilder:validation:OneOf
	AddressMatcher *Frontend `json:"addressMatcher,omitempty"`

	// ServiceMatcher specifies Kubernetes service and port that matches
	// traffic to be redirected.
	//
	// +kubebuilder:validation:OneOf
	ServiceMatcher *ServiceInfo `json:"serviceMatcher,omitempty"`
}

// PortInfo specifies L4 port number and name along with the transport protocol
type PortInfo struct {
	// Port is an L4 port number. The string will be strictly parsed as a single uint16.
	//
	// +kubebuilder:validation:Pattern=`^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$`
	// +kubebuilder:validation:Required
	Port string `json:"port"`

	// Protocol is the L4 protocol.
	// Accepted values: "TCP", "UDP"
	//
	// +kubebuilder:validation:Enum=TCP;UDP
	// +kubebuilder:validation:Required
	Protocol api.L4Proto `json:"protocol"`

	// Name is a port name, which must contain at least one [a-z],
	// and may also contain [0-9] and '-' anywhere except adjacent to another
	// '-' or in the beginning or the end.
	//
	// +kubebuilder:validation:Pattern=`^([0-9]{1,4})|([a-zA-Z0-9]-?)*[a-zA-Z](-?[a-zA-Z0-9])*$`
	// +kubebuilder:validation:Optional
	Name string `json:"name"`
}

type ServiceInfo struct {
	// Name is the name of a destination Kubernetes service that identifies traffic
	// to be redirected.
	// The service type needs to be ClusterIP.
	//
	// Example:
	// When this field is populated with 'serviceName:myService', all the traffic
	// destined to the cluster IP of this service at the (specified)
	// service port(s) will be redirected.
	//
	// +kubebuilder:validation:Required
	Name string `json:"serviceName"`

	// Namespace is the Kubernetes service namespace.
	// The service namespace must match the namespace of the parent Local
	// Redirect Policy.  For Cluster-wide Local Redirect Policy, this
	// can be any namespace.
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`

	// ToPorts is a list of destination service L4 ports with protocol for
	// traffic to be redirected. If not specified, traffic for all the service
	// ports will be redirected.
	// When multiple ports are specified, the ports must be named.
	//
	// +kubebuilder:validation:Optional
	ToPorts []PortInfo `json:"toPorts,omitempty"`
}

// RedirectBackend is a backend configuration that determines where traffic needs to be redirected to.
type RedirectBackend struct {
	// LocalEndpointSelector selects node local pod(s) where traffic is redirected to.
	//
	// +kubebuilder:validation:Required
	LocalEndpointSelector slim_metav1.LabelSelector `json:"localEndpointSelector"`

	// ToPorts is a list of L4 ports with protocol of node local pod(s) where traffic
	// is redirected to.
	// When multiple ports are specified, the ports must be named.
	//
	// +kubebuilder:validation:Required
	ToPorts []PortInfo `json:"toPorts"`
}

// CiliumLocalRedirectPolicySpec specifies the configurations for redirecting traffic
// within a node.
type CiliumLocalRedirectPolicySpec struct {
	// RedirectFrontend specifies frontend configuration to redirect traffic from.
	// It can not be empty.
	//
	// +kubebuilder:validation:Required
	RedirectFrontend RedirectFrontend `json:"redirectFrontend"`

	// RedirectBackend specifies backend configuration to redirect traffic to.
	// It can not be empty.
	//
	// +kubebuilder:validation:Required
	RedirectBackend RedirectBackend `json:"redirectBackend"`

	// Description can be used by the creator of the policy to describe the
	// purpose of this policy.
	//
	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`
}

// CiliumLocalRedirectPolicyStatus is the status of a Local Redirect Policy.
type CiliumLocalRedirectPolicyStatus struct {
	// TODO Define status(aditi)
	OK bool `json:"ok,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumLocalRedirectPolicyList is a list of CiliumLocalRedirectPolicy objects.
type CiliumLocalRedirectPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumLocalRedirectPolicy
	Items []CiliumLocalRedirectPolicy `json:"items"`
}

// SanitizePortInfo sanitizes all the fields in the PortInfo.
// It returns port number, name, and protocol derived from the given input  and error (failure cases).
func (pInfo *PortInfo) SanitizePortInfo(checkNamedPort bool) (uint16, string, lb.L4Type, error) {
	var (
		pInt     uint16
		pName    string
		protocol lb.L4Type
	)
	// Sanitize port
	if pInfo.Port == "" {
		return pInt, pName, protocol, fmt.Errorf("port must be specified")
	} else {
		p, err := strconv.ParseUint(pInfo.Port, 0, 16)
		if err != nil {
			return pInt, pName, protocol, fmt.Errorf("unable to parse port: %v", err)
		}
		if p == 0 {
			return pInt, pName, protocol, fmt.Errorf("port cannot be 0")
		}
		pInt = uint16(p)
	}
	// Sanitize name
	if checkNamedPort {
		if pInfo.Name == "" {
			return pInt, pName, protocol, fmt.Errorf("port %s in the local "+
				"redirect policy spec must have a valid IANA_SVC_NAME, as there are multiple ports", pInfo.Port)

		}
		if !iana.IsSvcName(pInfo.Name) {
			return pInt, pName, protocol, fmt.Errorf("port name %s isn't a "+
				"valid IANA_SVC_NAME", pInfo.Name)
		}
	}
	pName = strings.ToLower(pInfo.Name) // Normalize for case insensitive comparison

	// Sanitize protocol
	var err error
	protocol, err = lb.NewL4Type(string(pInfo.Protocol))
	if err != nil {
		return pInt, pName, protocol, err
	}
	return pInt, pName, protocol, nil
}
