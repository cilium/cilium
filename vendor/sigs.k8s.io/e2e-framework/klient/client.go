/*
Copyright 2021 The Kubernetes Authors.

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

package klient

import (
	"k8s.io/client-go/rest"
	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
)

// Client stores values to interact with the
// API-server.
type Client interface {
	// RESTConfig returns the *rest.Config associated with this client.
	RESTConfig() *rest.Config
	// Resources returns a *Resources type to access resource CRUD operations.
	// This method takes zero or at most 1 namespace (more will panic) that
	// can be used in List operations.
	Resources(...string) *resources.Resources
}

type client struct {
	cfg       *rest.Config
	resources *resources.Resources
}

// New returns a new Client value
func New(cfg *rest.Config) (Client, error) {
	res, err := resources.New(cfg)
	if err != nil {
		return nil, err
	}
	return &client{cfg: cfg, resources: res}, nil
}

// NewWithKubeConfigFile creates a client using the kubeconfig filePath
func NewWithKubeConfigFile(filePath string) (Client, error) {
	cfg, err := conf.New(filePath)
	if err != nil {
		return nil, err
	}
	return New(cfg)
}

// RESTConfig returns the *rest.Config value associated
// with this client.
func (c *client) RESTConfig() *rest.Config {
	return c.cfg
}

// Resources returns *Resources value to access CRUD object
// operations. It takes 0 or, at most, 1 namespace, or panics.
func (c *client) Resources(namespace ...string) *resources.Resources {
	switch len(namespace) {
	case 0:
		return c.resources.WithNamespace("")
	case 1:
		return c.resources.WithNamespace(namespace[0])
	default:
		panic("too many namespaces provided")
	}
}
