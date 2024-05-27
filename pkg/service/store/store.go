// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"

	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// ServiceStorePrefix is the kvstore prefix of the shared store
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	ServiceStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "services", "v1")
)

// ServiceMerger is the interface to be implemented by the owner of local
// services. The functions have to merge service updates and deletions with
// local services to provide a shared view.
type ServiceMerger interface {
	MergeClusterServiceUpdate(service *ClusterService, swg *lock.StoppableWaitGroup)
	MergeClusterServiceDelete(service *ClusterService, swg *lock.StoppableWaitGroup)
}

// PortConfiguration is the L4 port configuration of a frontend or backend. The
// map is indexed by the name of the port and the value constains the L4 port
// and protocol.
//
// +deepequal-gen=true
type PortConfiguration map[string]*loadbalancer.L4Addr

// ClusterService is the definition of a service in a cluster
//
// WARNING - STABLE API: Any change to this structure must be done in a
// backwards compatible way.
//
// +k8s:deepcopy-gen=true
type ClusterService struct {
	// Cluster is the cluster name the service is configured in
	Cluster string `json:"cluster"`

	// Namespace is the cluster namespace the service is configured in
	Namespace string `json:"namespace"`

	// Name is the name of the service. It must be unique within the
	// namespace of the cluster
	Name string `json:"name"`

	// Frontends is a map indexed by the frontend IP address
	Frontends map[string]PortConfiguration `json:"frontends"`

	// Backends is map indexed by the backend IP address
	Backends map[string]PortConfiguration `json:"backends"`

	// Hostnames is map indexed by the backend IP address
	Hostnames map[string]string `json:"hostnames"`

	// Labels are the labels of the service
	Labels map[string]string `json:"labels"`

	// Selector is the label selector used to select backends
	Selector map[string]string `json:"selector"`

	// IncludeExternal is true when external endpoints from other clusters
	// should be included
	IncludeExternal bool `json:"includeExternal"`

	// Shared is true when the service should be exposed/shared to other clusters
	Shared bool `json:"shared"`

	// ClusterID is the cluster ID the service is configured in
	ClusterID uint32 `json:"clusterID"`
}

func (s *ClusterService) String() string {
	return s.Cluster + "/" + s.Namespace + "/" + s.Name
}

// NamespaceServiceName returns the namespace and service name
func (s *ClusterService) NamespaceServiceName() types.NamespacedName {
	return types.NamespacedName{Name: s.Name, Namespace: s.Namespace}
}

// GetKeyName returns the kvstore key to be used for the global service
func (s *ClusterService) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(s.Cluster, s.Namespace, s.Name)
}

// DeepKeyCopy creates a deep copy of the LocalKey
func (s *ClusterService) DeepKeyCopy() store.LocalKey {
	return s.DeepCopy()
}

// Marshal returns the global service object as JSON byte slice
func (s *ClusterService) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// Unmarshal parses the JSON byte slice and updates the global service receiver
func (s *ClusterService) Unmarshal(_ string, data []byte) error {
	newService := NewClusterService("", "")

	if err := json.Unmarshal(data, &newService); err != nil {
		return err
	}

	if err := newService.validate(); err != nil {
		return err
	}

	*s = newService

	return nil
}

func (s *ClusterService) validate() error {
	switch {
	case s.Cluster == "":
		return errors.New("cluster is unset")
	case s.Namespace == "":
		return errors.New("namespace is unset")
	case s.Name == "":
		return errors.New("name is unset")
	}

	// Skip the ClusterID check if it matches the local one, as we assume that
	// it has already been validated, and to allow it to be zero.
	if s.ClusterID != option.Config.ClusterID {
		if err := cmtypes.ValidateClusterID(s.ClusterID); err != nil {
			return err
		}
	}

	for address := range s.Frontends {
		if _, err := netip.ParseAddr(address); err != nil {
			return err
		}
	}

	for address := range s.Backends {
		if _, err := netip.ParseAddr(address); err != nil {
			return err
		}
	}

	return nil
}

// NewClusterService returns a new cluster service definition
func NewClusterService(name, namespace string) ClusterService {
	return ClusterService{
		Name:      name,
		Namespace: namespace,
		Frontends: map[string]PortConfiguration{},
		Backends:  map[string]PortConfiguration{},
		Hostnames: map[string]string{},
		Labels:    map[string]string{},
		Selector:  map[string]string{},
	}
}

// ValidatingClusterService wraps a ClusterService to perform additional
// validation at unmarshal time.
type ValidatingClusterService struct {
	ClusterService

	validators []clusterServiceValidator
}

type clusterServiceValidator func(key string, svc *ClusterService) error

func (vcs *ValidatingClusterService) Unmarshal(key string, data []byte) error {
	if err := vcs.ClusterService.Unmarshal(key, data); err != nil {
		return err
	}

	for _, validator := range vcs.validators {
		if err := validator(key, &vcs.ClusterService); err != nil {
			return err
		}
	}

	return nil
}

// ClusterNameValidator returns a validator enforcing that the cluster field
// of the unmarshaled service matches the provided one.
func ClusterNameValidator(clusterName string) clusterServiceValidator {
	return func(_ string, svc *ClusterService) error {
		if svc.Cluster != clusterName {
			return fmt.Errorf("unexpected cluster name: got %s, expected %s", svc.Cluster, clusterName)
		}
		return nil
	}
}

// NamespacedNameValidator returns a validator enforcing that the namespaced
// name of the unmarshaled service matches the kvstore key.
func NamespacedNameValidator() clusterServiceValidator {
	return func(key string, svc *ClusterService) error {
		if got := svc.NamespaceServiceName().String(); got != key {
			return fmt.Errorf("namespaced name does not match key: got %s, expected %s", got, key)
		}
		return nil
	}
}

// ClusterIDValidator returns a validator enforcing that the cluster ID of the
// unmarshaled service matches the provided one. The access to the provided
// clusterID value is not synchronized, and it shall not be mutated concurrently.
func ClusterIDValidator(clusterID *uint32) clusterServiceValidator {
	return func(_ string, svc *ClusterService) error {
		if svc.ClusterID != *clusterID {
			return fmt.Errorf("unexpected cluster ID: got %d, expected %d", svc.ClusterID, *clusterID)
		}
		return nil
	}
}

// KeyCreator returns a store.KeyCreator for ClusterServices, configuring the
// specified extra validators.
func KeyCreator(validators ...clusterServiceValidator) store.KeyCreator {
	return func() store.Key {
		return &ValidatingClusterService{validators: validators}
	}
}

type clusterServiceObserver struct {
	// merger is the interface responsible to merge service and
	// endpoints into an existing cache
	merger ServiceMerger

	// swg provides a mechanism to know when the services were synchronized
	// with the datapath.
	swg *lock.StoppableWaitGroup
}

// OnUpdate is called when a service in a remote cluster is updated
func (c *clusterServiceObserver) OnUpdate(key store.Key) {
	if svc, ok := key.(*ValidatingClusterService); ok {
		scopedLog := log.WithField(logfields.ServiceName, svc.String())
		scopedLog.Debugf("Update event of cluster service %#v", svc)

		c.merger.MergeClusterServiceUpdate(&svc.ClusterService, c.swg)
	} else {
		log.Warningf("Received unexpected cluster service update object %+v", key)
	}
}

// OnDelete is called when a service in a remote cluster is deleted
func (c *clusterServiceObserver) OnDelete(key store.NamedKey) {
	if svc, ok := key.(*ValidatingClusterService); ok {
		scopedLog := log.WithField(logfields.ServiceName, svc.String())
		scopedLog.Debugf("Delete event of cluster service %#v", svc)

		c.merger.MergeClusterServiceDelete(&svc.ClusterService, c.swg)
	} else {
		log.Warningf("Received unexpected cluster service delete object %+v", key)
	}
}

// JoinClusterServices starts a controller for syncing services from the kvstore
func JoinClusterServices(merger ServiceMerger, clusterName string) {
	swg := lock.NewStoppableWaitGroup()

	log.Info("Enumerating cluster services")
	// JoinSharedStore performs initial sync of services
	_, err := store.JoinSharedStore(store.Configuration{
		Prefix: path.Join(ServiceStorePrefix, clusterName),
		KeyCreator: KeyCreator(
			ClusterNameValidator(clusterName),
			NamespacedNameValidator(),
		),
		Observer: &clusterServiceObserver{
			merger: merger,
			swg:    swg,
		},
	})
	if err != nil {
		log.WithError(err).Fatal("Enumerating cluster services failed")
	}
	swg.Stop()
}
