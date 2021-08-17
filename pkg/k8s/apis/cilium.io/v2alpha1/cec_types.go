// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	"bytes"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	anypb "google.golang.org/protobuf/types/known/anypb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/option"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumenvoyconfig",path="ciliumenvoyconfigs",scope="Cluster",shortName={cec}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="The age of the identity",name="Age",type=date
// +kubebuilder:storageversion

type CiliumEnvoyConfig struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// +k8s:openapi-gen=false
	// +kubebuilder:validation:Type=object
	Spec CiliumEnvoyConfigSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumEnvoyConfigList is a list of CiliumEnvoyConfig objects.
type CiliumEnvoyConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEnvoyConfig.
	Items []CiliumEnvoyConfig `json:"items"`
}

type CiliumEnvoyConfigSpec struct {
	// Services specifies Kubernetes services for which traffic is
	// forwarded to an Envoy listener for L7 load balancing. Backends
	// of these services are automatically synced to Envoy usign EDS.
	//
	// +kubebuilder:validation:Optional
	Services []*ServiceListener `json:"services,omitempty"`

	// BackendServices specifies Kubernetes services whose backends
	// are automatically synced to Envoy usign EDS.
	//
	// +kubebuilder:validation:Optional
	BackendServices []*Service `json:"backendServices,omitempty"`

	// Ingress must be set to 'true' when listeners included in
	// 'resources' are ingress listeners (capturing traffic before
	// entering pods). Defaults to 'false' for egress listeners
	// (capturing traffic exiting pods). This implies that all
	// listeners in 'resources' must be either ingress or egress
	// listeners.
	//
	// This setting directs policy principal selection
	// (destination for ingress, source for egress) and must be
	// set properly.
	//
	// +kubebuilder:validation:Optional
	Ingress bool `json:"ingress,omitempty"`

	// Envoy xDS resources, a list of the following Envoy resource types:
	// type.googleapis.com/envoy.config.listener.v3.Listener,
	// type.googleapis.com/envoy.config.route.v3.RouteConfiguration,
	// type.googleapis.com/envoy.config.cluster.v3.Cluster,
	// type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment, and
	// type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret.
	//
	// +kubebuilder:validation:Required
	Resources []XDSResource `json:"resources,omitempty"`
}

type Service struct {
	// Name is the name of a destination Kubernetes service that identifies traffic
	// to be redirected.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace is the Kubernetes service namespace.
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
}

type ServiceListener struct {
	// Name is the name of a destination Kubernetes service that identifies traffic
	// to be redirected.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace is the Kubernetes service namespace.
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`

	// Listener specifies the name of the Envoy listener the
	// service traffic is redirected to. The listener must be
	// specified in the Envoy 'resources' of the same
	// CiliumEnvoyConfig.
	//
	// If omitted, the first listener specified in 'resources' is
	// used.
	//
	// +kubebuilder:validation:Optional
	Listener string `json:"listener"`
}

// +kubebuilder:pruning:PreserveUnknownFields
type XDSResource struct {
	*anypb.Any `json:"-"`
}

// DeepCopyInto deep copies 'in' into 'out'.
func (in *XDSResource) DeepCopyInto(out *XDSResource) {
	out.Any, _ = proto.Clone(in.Any).(*anypb.Any)
}

// Equal returns 'true' if 'a' and 'b' are equal.
func (a *XDSResource) DeepEqual(b *XDSResource) bool {
	return proto.Equal(a.Any, b.Any)
}

// MarshalJSON ensures that the unstructured object produces proper
// JSON when passed to Go's standard JSON library.
func (u *XDSResource) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(u.Any)
}

// UnmarshalJSON ensures that the unstructured object properly decodes
// JSON when passed to Go's standard JSON library.
func (u *XDSResource) UnmarshalJSON(b []byte) (err error) {
	if option.Config.Debug {
		var buf bytes.Buffer
		json.Indent(&buf, b, "", "\t")
		log.Debugf("CEC UnmarshalJSON: %s", buf.String())
	}
	// xDS resources are not validated in K8s, recover from possible panics
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("CEC JSON decoding paniced: %v", r)
		}
	}()
	u.Any = &anypb.Any{}
	err = protojson.Unmarshal(b, u.Any)
	if option.Config.Debug {
		log.Debugf("CEC unmarshaled XDS Resource: %v", prototext.Format(u.Any))
	}
	return err
}
