/*
Copyright 2016 The Kubernetes Authors.

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

package services

import (
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/api"
	namespacecontroller "k8s.io/kubernetes/pkg/controller/namespace"
)

const (
	// ncName is the name of namespace controller
	ncName = "namespace-controller"
	// ncResyncPeriod is resync period of the namespace controller
	ncResyncPeriod = 5 * time.Minute
	// ncConcurrency is concurrency of the namespace controller
	ncConcurrency = 2
)

// NamespaceController is a server which manages namespace controller.
type NamespaceController struct {
	host   string
	stopCh chan struct{}
}

// NewNamespaceController creates a new namespace controller.
func NewNamespaceController(host string) *NamespaceController {
	return &NamespaceController{host: host, stopCh: make(chan struct{})}
}

// Start starts the namespace controller.
func (n *NamespaceController) Start() error {
	// Use the default QPS
	config := restclient.AddUserAgent(&restclient.Config{Host: n.host}, ncName)
	client, err := clientset.NewForConfig(config)
	if err != nil {
		return err
	}
	clientPool := dynamic.NewClientPool(config, api.Registry.RESTMapper(), dynamic.LegacyAPIPathResolverFunc)
	discoverResourcesFn := client.Discovery().ServerPreferredNamespacedResources
	informerFactory := informers.NewSharedInformerFactory(client, ncResyncPeriod)
	nc := namespacecontroller.NewNamespaceController(
		client,
		clientPool,
		discoverResourcesFn,
		informerFactory.Core().V1().Namespaces(),
		ncResyncPeriod, v1.FinalizerKubernetes,
	)
	informerFactory.Start(n.stopCh)
	go nc.Run(ncConcurrency, n.stopCh)
	return nil
}

// Stop stops the namespace controller.
func (n *NamespaceController) Stop() error {
	close(n.stopCh)
	return nil
}

// Name returns the name of namespace controller.
func (n *NamespaceController) Name() string {
	return ncName
}
