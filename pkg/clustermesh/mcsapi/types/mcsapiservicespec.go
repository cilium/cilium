// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

var (
	// ServiceExportStorePrefix is the kvstore prefix of the shared store
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	ServiceExportStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "serviceexports", "v1")
)

type MCSAPIServiceSpec struct {
	// Cluster is the cluster name the service is configured in
	Cluster string `json:"cluster"`

	// Name is the name of the ServiceImport or ServiceExport parent resources.
	Name string `json:"name"`

	// Namespace is the cluster namespace the service is configured in
	Namespace string `json:"namespace"`

	// Annotations contains the exported annotations
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels contains the exported labels
	Labels map[string]string `json:"labels,omitempty"`

	// LegacyLabels contains the exported labels.
	// Deprecated: Use Labels instead, this is kept for backward compatibility
	LegacyLabels map[string]string `json:"Labels,omitempty"`

	// LegacyAnnotations contains the exported annotations.
	// Deprecated: Use Annotations instead, this is kept for backward compatibility
	LegacyAnnotations map[string]string `json:"Annotations,omitempty"`

	// ExportCreationTimestamp is the timestamp representing when the
	// ServiceExport object was created. It is used for conflict resolution.
	ExportCreationTimestamp metav1.Time `json:"exportCreationTimestamp"`

	// Ports are the list of ports of the Service in MCS API format
	Ports []mcsapiv1alpha1.ServicePort `json:"ports"`

	// Type defines the type of this service.
	// Must be ClusterSetIP or Headless.
	Type mcsapiv1alpha1.ServiceImportType `json:"type"`

	// Supports "ClientIP" and "None". Used to maintain session affinity.
	// Enable client IP based session affinity.
	// Must be ClientIP or None.
	// Defaults to None.
	// Ignored when type is Headless
	// More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
	SessionAffinity corev1.ServiceAffinity `json:"sessionAffinity"`

	// SessionAffinityConfig contains session affinity configuration.
	SessionAffinityConfig *corev1.SessionAffinityConfig `json:"sessionAffinityConfig,omitempty"`

	// IPFamilies identifies all the IPFamilies assigned for this ServiceImport.
	IPFamilies []corev1.IPFamily `json:"ipFamilies,omitempty"`

	// InternalTrafficPolicy describes how nodes distribute service traffic they
	// receive on the ClusterIP. If set to "Local", the proxy will assume that pods
	// only want to talk to endpoints of the service on the same node as the pod,
	// dropping the traffic if there are no local endpoints. The default value,
	// "Cluster", uses the standard behavior of routing to all endpoints evenly
	// (possibly modified by topology and other features).
	InternalTrafficPolicy *corev1.ServiceInternalTrafficPolicy `json:"internalTrafficPolicy,omitempty"`

	// TrafficDistribution offers a way to express preferences for how traffic
	// is distributed to Service endpoints. Implementations can use this field
	// as a hint, but are not required to guarantee strict adherence. If the
	// field is not set, the implementation will apply its default routing
	// strategy. If set to "PreferClose", implementations should prioritize
	// endpoints that are in the same zone.
	TrafficDistribution *string `json:"trafficDistribution,omitempty"`
}

// GetKeyName returns the kvstore key to be used for MCSAPIServiceSpec
func (s *MCSAPIServiceSpec) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(s.Cluster, s.Namespace, s.Name)
}

// NamespaceServiceName returns the namespace and service name
func (s *MCSAPIServiceSpec) NamespacedName() types.NamespacedName {
	return types.NamespacedName{Name: s.Name, Namespace: s.Namespace}
}

// Marshal returns the MCS-API Service Spec object as JSON byte slice
func (s *MCSAPIServiceSpec) Marshal() ([]byte, error) {
	// Populate legacy fields for forward compatibility
	s.LegacyAnnotations = s.Annotations
	s.LegacyLabels = s.Labels
	return json.Marshal(s)
}

// Unmarshal parses the JSON byte slice and updates the MCS-API Service Spec receiver
func (s *MCSAPIServiceSpec) Unmarshal(_ string, data []byte) error {
	newMCSAPIServiceSpec := MCSAPIServiceSpec{}

	if err := json.Unmarshal(data, &newMCSAPIServiceSpec); err != nil {
		return err
	}

	// Handle backward compatibility of old annotations/labels fields
	if len(newMCSAPIServiceSpec.Annotations) == 0 {
		newMCSAPIServiceSpec.Annotations = newMCSAPIServiceSpec.LegacyAnnotations
	}
	if len(newMCSAPIServiceSpec.Labels) == 0 {
		newMCSAPIServiceSpec.Labels = newMCSAPIServiceSpec.LegacyLabels
	}
	newMCSAPIServiceSpec.LegacyAnnotations = nil
	newMCSAPIServiceSpec.LegacyLabels = nil

	if err := newMCSAPIServiceSpec.validate(); err != nil {
		return err
	}

	*s = newMCSAPIServiceSpec

	return nil
}

func (s *MCSAPIServiceSpec) validate() error {
	switch {
	case s.Cluster == "":
		return errors.New("cluster is unset")
	case s.Namespace == "":
		return errors.New("namespace is unset")
	case s.Name == "":
		return errors.New("name is unset")
	case s.ExportCreationTimestamp.IsZero():
		return errors.New("exportCreationTimestamp is unset")
	case s.Type != mcsapiv1alpha1.ClusterSetIP && s.Type != mcsapiv1alpha1.Headless:
		return fmt.Errorf("type is unknown: %s", s.Type)
	case s.SessionAffinity != corev1.ServiceAffinityClientIP && s.SessionAffinity != corev1.ServiceAffinityNone:
		return fmt.Errorf("session affinity is unknown: %s", s.SessionAffinity)
	case s.InternalTrafficPolicy != nil &&
		*s.InternalTrafficPolicy != corev1.ServiceInternalTrafficPolicyCluster &&
		*s.InternalTrafficPolicy != corev1.ServiceInternalTrafficPolicyLocal:
		return fmt.Errorf("internal traffic policy is unknown: %s", *s.InternalTrafficPolicy)
	case s.TrafficDistribution != nil &&
		*s.TrafficDistribution != corev1.ServiceTrafficDistributionPreferClose &&
		*s.TrafficDistribution != corev1.ServiceTrafficDistributionPreferSameZone &&
		*s.TrafficDistribution != corev1.ServiceTrafficDistributionPreferSameNode:
		return fmt.Errorf("traffic distribution is unknown: %s", *s.TrafficDistribution)
	}

	return nil
}

// ValidatingMCSAPIServiceSpec wraps a MCSAPIServiceSpec to perform additional
// validation at unmarshal time.
type ValidatingMCSAPIServiceSpec struct {
	MCSAPIServiceSpec

	validators []mcsAPIServiceSpecValidator
}

type mcsAPIServiceSpecValidator func(key string, mcsAPISvcSpec *MCSAPIServiceSpec) error

func (vcs *ValidatingMCSAPIServiceSpec) Unmarshal(key string, data []byte) error {
	if err := vcs.MCSAPIServiceSpec.Unmarshal(key, data); err != nil {
		return err
	}

	for _, validator := range vcs.validators {
		if err := validator(key, &vcs.MCSAPIServiceSpec); err != nil {
			return err
		}
	}

	return nil
}

// ClusterNameValidator returns a validator enforcing that the cluster field
// of the unmarshaled service matches the provided one.
func ClusterNameValidator(clusterName string) mcsAPIServiceSpecValidator {
	return func(_ string, mcsAPISvcSpec *MCSAPIServiceSpec) error {
		if mcsAPISvcSpec.Cluster != clusterName {
			return fmt.Errorf("unexpected cluster name: got %s, expected %s", mcsAPISvcSpec.Cluster, clusterName)
		}
		return nil
	}
}

// NamespacedNameValidator returns a validator enforcing that the namespaced
// name of the unmarshaled mcs service spec matches the kvstore key.
func NamespacedNameValidator() mcsAPIServiceSpecValidator {
	return func(key string, svc *MCSAPIServiceSpec) error {
		if got := svc.NamespacedName().String(); got != key {
			return fmt.Errorf("namespaced name does not match key: got %s, expected %s", got, key)
		}
		return nil
	}
}

// KeyCreator returns a store.KeyCreator for MCSAPIServiceSpec, configuring the
// specified extra validators.
func KeyCreator(validators ...mcsAPIServiceSpecValidator) store.KeyCreator {
	return func() store.Key {
		return &ValidatingMCSAPIServiceSpec{validators: validators}
	}
}

func toKubeIPFamilies(ipFamilies []slim_corev1.IPFamily) []corev1.IPFamily {
	kubeIPFamilies := make([]corev1.IPFamily, 0, len(ipFamilies))
	for _, ipFamily := range ipFamilies {
		kubeIPFamilies = append(kubeIPFamilies, corev1.IPFamily(ipFamily))
	}
	return kubeIPFamilies
}

func FromCiliumServiceToMCSAPIServiceSpec(clusterName string, svc *slim_corev1.Service, svcExport *mcsapiv1alpha1.ServiceExport) *MCSAPIServiceSpec {
	ports := make([]mcsapiv1alpha1.ServicePort, 0, len(svc.Spec.Ports))
	for _, port := range svc.Spec.Ports {
		ports = append(ports, mcsapiv1alpha1.ServicePort{
			Name:        port.Name,
			AppProtocol: port.AppProtocol,
			Protocol:    corev1.Protocol(port.Protocol),
			Port:        port.Port,
		})
	}
	mcsAPISvcType := mcsapiv1alpha1.ClusterSetIP
	if svc.Spec.ClusterIP == slim_corev1.ClusterIPNone {
		mcsAPISvcType = mcsapiv1alpha1.Headless
	}
	mcsAPISvcSpec := &MCSAPIServiceSpec{
		Cluster:         clusterName,
		Name:            svc.Name,
		Namespace:       svc.Namespace,
		Ports:           ports,
		Type:            mcsAPISvcType,
		SessionAffinity: corev1.ServiceAffinity(svc.Spec.SessionAffinity),
		IPFamilies:      toKubeIPFamilies(svc.Spec.IPFamilies),
		Annotations:     maps.Clone(svcExport.Spec.ExportedAnnotations),
		Labels:          maps.Clone(svcExport.Spec.ExportedLabels),
	}
	if svc.Spec.SessionAffinityConfig != nil &&
		svc.Spec.SessionAffinityConfig.ClientIP != nil &&
		svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds != nil {
		mcsAPISvcSpec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
			ClientIP: &corev1.ClientIPConfig{
				TimeoutSeconds: ptr.To(*svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds),
			},
		}
	}
	if svc.Spec.InternalTrafficPolicy != nil {
		mcsAPISvcSpec.InternalTrafficPolicy = ptr.To(corev1.ServiceInternalTrafficPolicy(*svc.Spec.InternalTrafficPolicy))
	}
	if svc.Spec.TrafficDistribution != nil {
		mcsAPISvcSpec.TrafficDistribution = ptr.To(*svc.Spec.TrafficDistribution)
	}

	mcsAPISvcSpec.ExportCreationTimestamp = svcExport.CreationTimestamp
	return mcsAPISvcSpec
}

// NewEmptyMCSAPIServiceSpec returns a MCSAPIServiceSpec with only the fields
// needed to retrieve from the kvstore
func NewEmptyMCSAPIServiceSpec(clusterName, namespace, name string) *MCSAPIServiceSpec {
	return &MCSAPIServiceSpec{
		Cluster:   clusterName,
		Namespace: namespace,
		Name:      name,
	}
}
