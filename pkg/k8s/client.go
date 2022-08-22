// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"

	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
)

var (
	// k8sCLI is the default client.
	k8sCLI = &K8sClient{}

	// k8sWatcherCLI is the client dedicated k8s structure watchers.
	k8sWatcherCLI = &K8sSlimClient{}

	// k8sCiliumCLI is the default Cilium client.
	k8sCiliumCLI = &K8sCiliumClient{}

	// k8sCiliumCLI is the dedicated apiextensions client.
	k8sAPIExtCLI = &K8sAPIExtensionsClient{}

	// k8sAPIExtWatcherCLI is the client dedicated k8s structure watchers.
	k8sAPIExtWatcherCLI = &K8sAPIExtensionsClient{}
)

func SetClients(normal kubernetes.Interface, slim slimclientset.Interface, cilium clientset.Interface, apiext apiextclientset.Interface) {
	k8sCLI.Interface = normal
	k8sWatcherCLI.Interface = slim
	k8sCiliumCLI.Interface = cilium
	k8sAPIExtCLI = &K8sAPIExtensionsClient{apiext}
	k8sAPIExtWatcherCLI = &K8sAPIExtensionsClient{apiext}
}

// Client returns the default Kubernetes client.
func Client() *K8sClient {
	return k8sCLI
}

// WatcherClient returns the client dedicated to K8s watchers.
func WatcherClient() *K8sSlimClient {
	return k8sWatcherCLI
}

// CiliumClient returns the default Cilium Kubernetes client.
func CiliumClient() *K8sCiliumClient {
	return k8sCiliumCLI
}

// APIExtClient returns the default API Extension client.
func APIExtClient() *K8sAPIExtensionsClient {
	return k8sAPIExtCLI
}

// WatcherAPIExtClient returns the client dedicated to API Extensions watchers.
func WatcherAPIExtClient() *K8sAPIExtensionsClient {
	return k8sAPIExtWatcherCLI
}
