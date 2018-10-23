// Copyright 2018 Authors of Cilium
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

package service

import (
	"encoding/json"
	"path"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

var (
	// ServiceStorePrefix is the kvstore prefix of the shared store
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	ServiceStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "services", "v1")
)

// ClusterService is the definition of a service in a cluster
//
// WARNING - STABLE API: Any change to this structure must be done in a
// backwards compatible way.
type ClusterService struct {
	// Cluster is the cluster name the service is configured in
	Cluster string `json:"cluster"`

	// Namespace is the cluster namespace the service is configured in
	Namespace string `json:"namespace"`

	// Name is the name of the service. It must be unique within the
	// namespace of the cluster
	Name string `json:"name"`

	// FrontendIP is the frontend/service IP of the service
	FrontendIP string `json:"frontendIP"`

	// FrontendPorts is the list of portsgg
	FrontendPorts map[string]loadbalancer.L4Addr `json:"frontendPorts"`

	// BackendIPs is the list of IPs backing the service in the cluster
	BackendIPs []string `json:"backendIPs"`

	// BackendPorts is the list of ports for each backend IP. The name has
	// to map to the FrontendPorts
	BackendPorts map[string]loadbalancer.L4Addr `json:"backendPorts"`

	// Labels are the labels of the service
	Labels map[string]string `json:"labels"`

	// Selector is the label selector used to select backends
	Selector map[string]string `json:"selector"`
}

func (s *ClusterService) String() string {
	return s.Cluster + "/" + s.Namespace + ":" + s.Name
}

// GetKeyName returns the kvstore key to be used for the global service
func (s *ClusterService) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(s.Cluster, s.Namespace, s.Name)
}

// Marshal returns the global service object as JSON byte slice
func (s *ClusterService) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// Unmarshal parses the JSON byte slice and updates the global service receiver
func (s *ClusterService) Unmarshal(data []byte) error {
	return json.Unmarshal(data, s)
}

// NewClusterService returns a new cluster service definition
func NewClusterService(name, namespace string) ClusterService {
	return ClusterService{
		Name:          name,
		Namespace:     namespace,
		FrontendPorts: map[string]loadbalancer.L4Addr{},
		BackendPorts:  map[string]loadbalancer.L4Addr{},
		Labels:        map[string]string{},
		Selector:      map[string]string{},
	}
}
