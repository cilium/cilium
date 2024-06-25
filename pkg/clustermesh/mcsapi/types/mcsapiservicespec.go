// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	return json.Marshal(s)
}

// Unmarshal parses the JSON byte slice and updates the MCS-API Service Spec receiver
func (s *MCSAPIServiceSpec) Unmarshal(_ string, data []byte) error {
	newMCSAPIServiceSpec := MCSAPIServiceSpec{}

	if err := json.Unmarshal(data, &newMCSAPIServiceSpec); err != nil {
		return err
	}

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
	}
	if svc.Spec.SessionAffinityConfig != nil &&
		svc.Spec.SessionAffinityConfig.ClientIP != nil &&
		svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds != nil {

		timeoutSeconds := *svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds
		mcsAPISvcSpec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
			ClientIP: &corev1.ClientIPConfig{
				TimeoutSeconds: &timeoutSeconds,
			},
		}
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
