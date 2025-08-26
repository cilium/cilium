// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright The Kubernetes Authors.

package clientset

import (
	"fmt"
	"net/http"

	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"

	slim_apiextensionsv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client/clientset/versioned/typed/apiextensions/v1"
)

// Clientset contains the clients for groups. Each group has exactly one
// version included in a Clientset.
type Clientset struct {
	*apiextclientset.Clientset
	apiextensionsV1beta1 *apiextensionsv1beta1.ApiextensionsV1beta1Client
	apiextensionsV1      *apiextensionsv1.ApiextensionsV1Client
}

// ApiextensionsV1 retrieves the ApiextensionsV1Client
func (c *Clientset) ApiextensionsV1() apiextensionsv1.ApiextensionsV1Interface {
	return c.apiextensionsV1
}

// ApiextensionsV1beta1 retrieves the ApiextensionsV1beta1Client
func (c *Clientset) ApiextensionsV1beta1() apiextensionsv1beta1.ApiextensionsV1beta1Interface {
	return c.apiextensionsV1beta1
}

// NewForConfigAndClient creates a new Clientset for the given config and http client.
// Note the http client provided takes precedence over the configured transport values.
// If config's RateLimiter is not set and QPS and Burst are acceptable,
// NewForConfigAndClient will generate a rate-limiter in configShallowCopy.
func NewForConfigAndClient(c *rest.Config, httpClient *http.Client) (*Clientset, error) {
	configShallowCopy := *c
	if configShallowCopy.RateLimiter == nil && configShallowCopy.QPS > 0 {
		if configShallowCopy.Burst <= 0 {
			return nil, fmt.Errorf("burst is required to be greater than 0 when RateLimiter is not set and QPS is set to greater than 0")
		}
		configShallowCopy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(configShallowCopy.QPS, configShallowCopy.Burst)
	}
	var cs Clientset
	var err error
	cs.Clientset, err = apiextclientset.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}

	// Wrap extensionsV1 with our own implementation
	extensionsV1, err := slim_apiextensionsv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.apiextensionsV1 = apiextensionsv1.New(extensionsV1.RESTClient())

	return &cs, nil
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Clientset {
	var cs Clientset
	cs.Clientset = apiextclientset.NewForConfigOrDie(c)

	// Wrap extensionsV1 with our own implementation
	cs.apiextensionsV1 = apiextensionsv1.New(slim_apiextensionsv1.NewForConfigOrDie(c).RESTClient())

	return &cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.Clientset = apiextclientset.New(c)

	// Wrap extensionsV1 with our own implementation
	cs.apiextensionsV1 = apiextensionsv1.New(slim_apiextensionsv1.New(c).RESTClient())

	return &cs
}
