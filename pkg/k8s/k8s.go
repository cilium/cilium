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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// AnnotationParentPath is an optional annotation to the NetworkPolicy
	// resource which specifies the path to the parent policy node to which
	// all must be merged into.
	AnnotationParentPath = "io.cilium.parent"

	// DefaultPolicyParentPath is the default path to the policy node
	// received from kubernetes.
	DefaultPolicyParentPath = "k8s"

	// AnnotationName is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	AnnotationName = "io.cilium.name"

	// EnvNodeNameSpec is the environment label used by Kubernetes to
	// specify the node's name
	EnvNodeNameSpec = "K8S_NODE_NAME"
)

// Cilium policy labels
const (
	// PolicyLabelName is the name of the policy label which refers to the
	// k8s policy name
	PolicyLabelName = "io.cilium.k8s-policy-name"
)

// CreateClient creates a new client to access the Kubernetes API
func CreateClient(endpoint, kubeCfgPath string) (*kubernetes.Clientset, error) {
	var (
		config *rest.Config
		err    error
	)
	if kubeCfgPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeCfgPath)
	} else {
		config = &rest.Config{Host: endpoint}
		err = rest.SetKubernetesDefaults(config)
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}
