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

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// ThirdPartyResourceGroup is the name of the third party resource group
	ThirdPartyResourceGroup = "cilium.io"

	// ThirdPartyResourceVersion is the current version of the resource
	ThirdPartyResourceVersion = "v1"
)

func createConfig(endpoint, kubeCfgPath string) (*rest.Config, error) {
	if kubeCfgPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeCfgPath)
	}

	config := &rest.Config{Host: endpoint}
	err := rest.SetKubernetesDefaults(config)

	return config, err
}

// CreateClient creates a new client to access the Kubernetes API
func CreateClient(endpoint, kubeCfgPath string) (*kubernetes.Clientset, error) {
	config, err := createConfig(endpoint, kubeCfgPath)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		schema.GroupVersion{
			Group:   ThirdPartyResourceGroup,
			Version: ThirdPartyResourceVersion,
		},
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
		&metav1.ListOptions{},
		&metav1.DeleteOptions{},
	)

	return nil
}

// CreateTPRClient creates a new k8s client for third party resources
func CreateTPRClient(endpoint, kubeCfgPath string) (*rest.RESTClient, error) {
	config, err := createConfig(endpoint, kubeCfgPath)
	if err != nil {
		return nil, err
	}

	config.GroupVersion = &schema.GroupVersion{
		Group:   ThirdPartyResourceGroup,
		Version: ThirdPartyResourceVersion,
	}
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: api.Codecs}
	schemeBuilder := runtime.NewSchemeBuilder(addKnownTypes)
	schemeBuilder.AddToScheme(api.Scheme)

	return rest.RESTClientFor(config)
}
