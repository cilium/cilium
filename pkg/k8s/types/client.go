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
