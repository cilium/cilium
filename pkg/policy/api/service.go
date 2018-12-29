// Copyright 2016-2017 Authors of Cilium
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

package api

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/ip"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// K8sProvider represents Kubernetes services
	K8sProvider = "k8s"
)

var (
	serviceProviders = sync.Map{}
)

// ServiceSelector is a label selector for k8s services
type ServiceSelector EndpointSelector

func newServiceSelectorFromMatchLabels(matchLabels map[string]string) ServiceSelector {
	return ServiceSelector{
		LabelSelector: &metav1.LabelSelector{MatchLabels: matchLabels},
	}
}

// Service wraps around selectors for services
type Service struct {
	// K8sServiceSelector selects services by k8s labels and namespace
	K8sServiceSelector *K8sServiceSelectorNamespace `json:"k8sServiceSelector,omitempty"`
	// K8sService selects service by name and namespace pair
	K8sService *K8sServiceNamespace `json:"k8sService,omitempty"`
}

type K8sServiceIdentifier struct {
	K8sServiceNamespace
	Labels map[string]string
}

func NewK8sServiceIdentifier(name, namespace string, labels map[string]string) K8sServiceIdentifier {
	id := K8sServiceIdentifier{
		K8sServiceNamespace: K8sServiceNamespace{
			ServiceName: name,
			Namespace:   namespace,
		},
		Labels: map[string]string{},
	}

	for k, v := range labels {
		id.Labels[k] = v
	}

	return id
}

// K8sServiceNamespace is an abstraction for the k8s service + namespace types.
type K8sServiceNamespace struct {
	ServiceName string `json:"serviceName,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

// Matches returns true if the K8sServiceNamespace matches the specified
// identifier
func (k *K8sServiceNamespace) Matches(id K8sServiceIdentifier) bool {
	return k.ServiceName == id.ServiceName && k.Namespace == id.Namespace
}

// K8sServiceSelectorNamespace wraps service selector with namespace
type K8sServiceSelectorNamespace struct {
	Selector  ServiceSelector `json:"selector"`
	Namespace string          `json:"namespace,omitempty"`
}

// Matches returns true if the K8sServiceSelectorNamespace matches the
// specified identifier
func (k *K8sServiceSelectorNamespace) Matches(id K8sServiceIdentifier) bool {
	if k.Namespace != "" && k.Namespace != id.Namespace {
		return false
	}

	endpointSelector := EndpointSelector(k.Selector)
	endpointSelector.SyncRequirementsWithLabelSelector()

	return endpointSelector.Matches(labels.Set(id.Labels))
}

// GroupProviderFunc is a func that need to be register to be able to
// register a new provider in the platform.
type ServiceProviderFunc func(*Service) ([]net.IP, error)

// RegisterServicesProvider registers a new service provider
func RegisterServiceProvider(providerName string, callback ServiceProviderFunc) {
	serviceProviders.Store(providerName, callback)
}

// Matches returns true if the service selector matches the specified
// identifier
func (svc *Service) Matches(id K8sServiceIdentifier) bool {
	if svc.K8sService != nil && !svc.K8sService.Matches(id) {
		return false
	}

	if svc.K8sServiceSelector != nil && !svc.K8sServiceSelector.Matches(id) {
		return false
	}

	return true
}

// GetCidrSet will return a list of CIDRRule as a resulted of invoking the
// service providers
func (svc *Service) GetCidrSet() ([]CIDRRule, error) {
	callbackInterface, ok := serviceProviders.Load(K8sProvider)
	if !ok {
		return nil, fmt.Errorf("Provider %s is not registered", K8sProvider)
	}
	callback, ok := callbackInterface.(ServiceProviderFunc)
	if !ok {
		return nil, fmt.Errorf("Provider callback for %s is not a valid instance", K8sProvider)
	}
	ips, err := callback(svc)
	if err != nil {
		return nil, fmt.Errorf("Cannot retrieve CIDRSet from %s provider: %s", K8sProvider, err)
	}

	resultIps := ip.KeepUniqueIPs(ips)
	return IPsToCIDRRules(resultIps), nil
}
