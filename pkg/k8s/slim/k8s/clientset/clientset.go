// Copyright The Kubernetes Authors.
// Copyright 2020 Authors of Cilium
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

package clientset

import (
	"fmt"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	slim_discovery_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/discovery/v1beta1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/networking/v1"

	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	discoveryv1beta1 "k8s.io/client-go/kubernetes/typed/discovery/v1beta1"
	networkingv1 "k8s.io/client-go/kubernetes/typed/networking/v1"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"
)

// Clientset contains the clients for groups. Each group has exactly one
// version included in a Clientset.
type Clientset struct {
	*kubernetes.Clientset
	coreV1           *corev1.CoreV1Client
	discoveryV1beta1 *discoveryv1beta1.DiscoveryV1beta1Client
	networkingV1     *networkingv1.NetworkingV1Client
}

// CoreV1 retrieves the CoreV1Client
func (c *Clientset) CoreV1() corev1.CoreV1Interface {
	return c.coreV1
}

// DiscoveryV1beta1 retrieves the DiscoveryV1beta1Client
func (c *Clientset) DiscoveryV1beta1() discoveryv1beta1.DiscoveryV1beta1Interface {
	return c.discoveryV1beta1
}

// NetworkingV1 retrieves the NetworkingV1Client
func (c *Clientset) NetworkingV1() networkingv1.NetworkingV1Interface {
	return c.networkingV1
}

// NewForConfig creates a new Clientset for the given config.
// If config's RateLimiter is not set and QPS and Burst are acceptable,
// NewForConfig will generate a rate-limiter in configShallowCopy.
func NewForConfig(c *rest.Config) (*Clientset, error) {
	configShallowCopy := *c
	if configShallowCopy.RateLimiter == nil && configShallowCopy.QPS > 0 {
		if configShallowCopy.Burst <= 0 {
			return nil, fmt.Errorf("burst is required to be greater than 0 when RateLimiter is not set and QPS is set to greater than 0")
		}
		configShallowCopy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(configShallowCopy.QPS, configShallowCopy.Burst)
	}
	var cs Clientset
	var err error
	cs.Clientset, err = kubernetes.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}

	// Wrap coreV1 with our own implementation
	slimCoreV1, err := slim_corev1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.coreV1 = corev1.New(slimCoreV1.RESTClient())

	// Wrap discoveryV1beta1 with our own implementation
	slimDiscoveryV1beta1, err := slim_discovery_v1beta1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.discoveryV1beta1 = discoveryv1beta1.New(slimDiscoveryV1beta1.RESTClient())

	// Wrap networkingV1 with our own implementation
	slimNetworkingV1, err := slim_networkingv1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.networkingV1 = networkingv1.New(slimNetworkingV1.RESTClient())

	return &cs, nil
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Clientset {
	var cs Clientset
	cs.Clientset = kubernetes.NewForConfigOrDie(c)

	// Wrap coreV1 with our own implementation
	cs.coreV1 = corev1.New(slim_corev1.NewForConfigOrDie(c).RESTClient())

	// Wrap discoveryV1beta1 with our own implementation
	cs.discoveryV1beta1 = discoveryv1beta1.New(slim_discovery_v1beta1.NewForConfigOrDie(c).RESTClient())

	// Wrap networkingV1 with our own implementation
	cs.networkingV1 = networkingv1.New(slim_networkingv1.NewForConfigOrDie(c).RESTClient())

	return &cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.Clientset = kubernetes.New(c)

	// Wrap coreV1 with our own implementation
	cs.coreV1 = corev1.New(slim_corev1.New(c).RESTClient())

	// Wrap discoveryV1beta1 with our own implementation
	cs.discoveryV1beta1 = discoveryv1beta1.New(slim_discovery_v1beta1.New(c).RESTClient())

	// Wrap networkingV1 with our own implementation
	cs.networkingV1 = networkingv1.New(slim_networkingv1.New(c).RESTClient())

	return &cs
}
