// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright The Kubernetes Authors.

package clientset

import (
	"fmt"
	"net/http"

	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	discoveryv1 "k8s.io/client-go/kubernetes/typed/discovery/v1"
	discoveryv1beta1 "k8s.io/client-go/kubernetes/typed/discovery/v1beta1"
	networkingv1 "k8s.io/client-go/kubernetes/typed/networking/v1"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/discovery/v1"
	slim_discovery_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/discovery/v1beta1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/networking/v1"
)

// Clientset contains the clients for groups. Each group has exactly one
// version included in a Clientset.
type Clientset struct {
	*kubernetes.Clientset
	coreV1           *corev1.CoreV1Client
	discoveryV1beta1 *discoveryv1beta1.DiscoveryV1beta1Client
	discoveryV1      *discoveryv1.DiscoveryV1Client
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

// DiscoveryV1 retrieves the DiscoveryV1Client
func (c *Clientset) DiscoveryV1() discoveryv1.DiscoveryV1Interface {
	return c.discoveryV1
}

// NetworkingV1 retrieves the NetworkingV1Client
func (c *Clientset) NetworkingV1() networkingv1.NetworkingV1Interface {
	return c.networkingV1
}

// NewForConfigAndClient creates a new Clientset for the given config and http client.
// If config's RateLimiter is not set and QPS and Burst are acceptable,
// NewForConfig will generate a rate-limiter in configShallowCopy.
// Note the http client provided takes precedence over the configured transport values.
func NewForConfigAndClient(c *rest.Config, h *http.Client) (*Clientset, error) {
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
	slimCoreV1, err := slim_corev1.NewForConfigAndClient(&configShallowCopy, h)
	if err != nil {
		return nil, err
	}
	cs.coreV1 = corev1.New(slimCoreV1.RESTClient())

	// Wrap discoveryV1beta1 with our own implementation
	slimDiscoveryV1beta1, err := slim_discovery_v1beta1.NewForConfigAndClient(&configShallowCopy, h)
	if err != nil {
		return nil, err
	}
	cs.discoveryV1beta1 = discoveryv1beta1.New(slimDiscoveryV1beta1.RESTClient())

	// Wrap discoveryV1 with our own implementation
	slimDiscoveryV1, err := slim_discovery_v1.NewForConfigAndClient(&configShallowCopy, h)
	if err != nil {
		return nil, err
	}
	cs.discoveryV1 = discoveryv1.New(slimDiscoveryV1.RESTClient())

	// Wrap networkingV1 with our own implementation
	slimNetworkingV1, err := slim_networkingv1.NewForConfigAndClient(&configShallowCopy, h)
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

	// Wrap discoveryV1 with our own implementation
	cs.discoveryV1 = discoveryv1.New(slim_discovery_v1.NewForConfigOrDie(c).RESTClient())

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

	// Wrap discoveryV1 with our own implementation
	cs.discoveryV1 = discoveryv1.New(slim_discovery_v1.New(c).RESTClient())

	// Wrap networkingV1 with our own implementation
	cs.networkingV1 = networkingv1.New(slim_networkingv1.New(c).RESTClient())

	return &cs
}
