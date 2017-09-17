/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package internalversion

import (
	rest "k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/scheme"
)

type SchedulingInterface interface {
	RESTClient() rest.Interface
	PriorityClassesGetter
}

// SchedulingClient is used to interact with features provided by the scheduling.k8s.io group.
type SchedulingClient struct {
	restClient rest.Interface
}

func (c *SchedulingClient) PriorityClasses() PriorityClassInterface {
	return newPriorityClasses(c)
}

// NewForConfig creates a new SchedulingClient for the given config.
func NewForConfig(c *rest.Config) (*SchedulingClient, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &SchedulingClient{client}, nil
}

// NewForConfigOrDie creates a new SchedulingClient for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *SchedulingClient {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new SchedulingClient for the given RESTClient.
func New(c rest.Interface) *SchedulingClient {
	return &SchedulingClient{c}
}

func setConfigDefaults(config *rest.Config) error {
	g, err := scheme.Registry.Group("scheduling.k8s.io")
	if err != nil {
		return err
	}

	config.APIPath = "/apis"
	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}
	if config.GroupVersion == nil || config.GroupVersion.Group != g.GroupVersion.Group {
		gv := g.GroupVersion
		config.GroupVersion = &gv
	}
	config.NegotiatedSerializer = scheme.Codecs

	if config.QPS == 0 {
		config.QPS = 5
	}
	if config.Burst == 0 {
		config.Burst = 10
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *SchedulingClient) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
