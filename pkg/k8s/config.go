// Copyright 2017 Authors of Cilium
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
	"os"
	"strings"
)

var (
	// config is the configuration of Kubernetes related settings
	config configuration
)

type configuration struct {
	// APIServer is the address of the API server
	APIServer string

	// KubeconfigPath is the local path to the kubeconfig configuration
	// file on the filesystem
	KubeconfigPath string
}

// GetAPIServer returns the configured API server address
func GetAPIServer() string {
	return config.APIServer
}

// GetKubeconfigPath returns the configured path to the kubeconfig
// configuration file
func GetKubeconfigPath() string {
	return config.KubeconfigPath
}

// Configure sets the parameters of the Kubernetes package
func Configure(apiServer, kubeconfigPath string) {
	config.APIServer = apiServer
	config.KubeconfigPath = kubeconfigPath

	if IsEnabled() &&
		config.APIServer != "" &&
		!strings.HasPrefix(apiServer, "http") {
		config.APIServer = "http://" + apiServer
	}
}

// IsEnabled checks if Cilium is being used in tandem with Kubernetes.
func IsEnabled() bool {
	return config.APIServer != "" ||
		config.KubeconfigPath != "" ||
		(os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
			os.Getenv("KUBERNETES_SERVICE_PORT") != "")
}
