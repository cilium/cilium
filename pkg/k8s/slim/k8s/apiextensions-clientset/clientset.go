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

	slim_apiextensionsv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client/clientset/versioned/typed/apiextensions/v1"
	slim_apiextensionsv1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client/clientset/versioned/typed/apiextensions/v1beta1"

	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"
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
	cs.Clientset, err = apiextclientset.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}

	// Wrap extensionsV1Beta1 with our own implementation
	extensionsV1Beta1, err := slim_apiextensionsv1beta1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.apiextensionsV1beta1 = apiextensionsv1beta1.New(extensionsV1Beta1.RESTClient())

	// Wrap extensionsV1 with our own implementation
	extensionsV1, err := slim_apiextensionsv1.NewForConfig(&configShallowCopy)
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

	// Wrap extensionsV1Beta1 with our own implementation
	cs.apiextensionsV1beta1 = apiextensionsv1beta1.New(slim_apiextensionsv1beta1.NewForConfigOrDie(c).RESTClient())

	// Wrap extensionsV1 with our own implementation
	cs.apiextensionsV1 = apiextensionsv1.New(slim_apiextensionsv1.NewForConfigOrDie(c).RESTClient())

	return &cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.Clientset = apiextclientset.New(c)

	// Wrap extensionsV1Beta1 with our own implementation
	cs.apiextensionsV1beta1 = apiextensionsv1beta1.New(slim_apiextensionsv1beta1.New(c).RESTClient())

	// Wrap extensionsV1 with our own implementation
	cs.apiextensionsV1 = apiextensionsv1.New(slim_apiextensionsv1.New(c).RESTClient())

	return &cs
}
