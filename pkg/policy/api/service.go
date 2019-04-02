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
	"net"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// K8sProvider represents Kubernetes services
	K8sProvider = "k8s"
)

var (
	registeredProviders = providerRegister{
		providers: map[ProviderName]ServiceProviderFunc{},
	}
)

// ProviderName is a unique string identifying a service provider
type ProviderName string

type providerRegister struct {
	providers map[ProviderName]ServiceProviderFunc
	mutex     lock.RWMutex
}

// ServiceSelector is a label selector for k8s services
type ServiceSelector EndpointSelector

// NewServiceSelectorFromMatchLabels returns a new ServiceSelector based on a
// label based matchLabels
func NewServiceSelectorFromMatchLabels(matchLabels map[string]string) ServiceSelector {
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

// K8sServiceIdentifier contains all fields of a Kubernetes service used for
// identification purposes
type K8sServiceIdentifier struct {
	K8sServiceNamespace
	Labels map[string]string
}

// NewK8sServiceIdentifier returns a new service identifier based on the
// provided name, namespace and service labels
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

// ServiceProviderFunc is the function called to resolve a service selector to
// a list of IPs as owned by a particular service provider. GetCidrSet() calls
// all ServiceProviderFunc that have been registered via
// RegisterServiceProvider().
type ServiceProviderFunc func(*Service) []net.IP

// RegisterServiceProvider registers a new service provider
func RegisterServiceProvider(name ProviderName, callback ServiceProviderFunc) {
	registeredProviders.mutex.Lock()
	registeredProviders.providers[name] = callback
	registeredProviders.mutex.Unlock()
}

// UnregisterServiceProvider unregisters a service provider
func UnregisterServiceProvider(name ProviderName) {
	registeredProviders.mutex.Lock()
	delete(registeredProviders.providers, name)
	registeredProviders.mutex.Unlock()
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
func (svc *Service) GetCidrSet() []CIDRRule {
	registeredProviders.mutex.RLock()
	defer registeredProviders.mutex.RUnlock()

	ipList := []net.IP{}
	for _, callback := range registeredProviders.providers {
		ipList = append(ipList, callback(svc)...)
	}

	return IPsToCIDRRules(ip.KeepUniqueIPs(ipList))
}
