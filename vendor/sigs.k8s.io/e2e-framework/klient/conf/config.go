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

// Package conf is used to create an instance of *rest.Config
package conf

import (
	"flag"
	"os"
	"os/user"
	"path"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DefaultClusterContext default cluster context
var DefaultClusterContext = ""

// New returns Kubernetes configuration value of type *rest.Config.
// filename is kubeconfig file
func New(fileName string) (*rest.Config, error) {
	// if filename is not provided assume in-cluster-config
	if fileName == "" {
		return rest.InClusterConfig()
	}

	// create the config object from k8s config path
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: fileName}, &clientcmd.ConfigOverrides{}).ClientConfig()
}

// NewWithContextName returns k8s config value of type *rest.Config
func NewWithContextName(fileName, context string) (*rest.Config, error) {
	// create the config object from k8s config path and context
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: fileName},
		&clientcmd.ConfigOverrides{
			CurrentContext: context,
		}).ClientConfig()
}

// NewInCluster for clients that expect to be
// running inside a pod on kubernetes
func NewInCluster() (*rest.Config, error) {
	return rest.InClusterConfig()
}

// ResolveKubeConfigFile returns the kubeconfig file from
// either flag --kubeconfig or env KUBECONFIG.
// If flag.Parsed() is true then lookup for --kubeconfig flag.
// If --kubeconfig, or KUBECONFIG, or  $HOME/.kube/config not provided then
// assume in cluster.
func ResolveKubeConfigFile() string {
	var kubeConfigPath string

	// If a flag --kubeconfig  is specified with the config location, use that
	if flag.Parsed() {
		f := flag.Lookup("kubeconfig")
		if f != nil && f.Value.String() != "" {
			return f.Value.String()
		}
	}

	// if KUBECONFIG env is defined then use that
	kubeConfigPath = os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if kubeConfigPath != "" {
		return kubeConfigPath
	}

	var (
		homeDir string
		ok      bool
	)

	// check if $HOME/.kube/config is present
	// if $HOME is unset, get it from current user
	if homeDir, ok = os.LookupEnv("HOME"); !ok {
		u, err := user.Current()
		if err != nil {
			// consider it as in-cluster-config
			return ""
		}

		kubeConfigPath = path.Join(u.HomeDir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
	} else {
		kubeConfigPath = path.Join(homeDir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
	}

	// check if the config path exists
	if fileExists(kubeConfigPath) {
		return kubeConfigPath
	}

	return ""
}

// ResolveClusterContext returns cluster context name based on --context flag.
func ResolveClusterContext() string {
	// If a flag --kube-context is specified use that
	if flag.Parsed() {
		f := flag.Lookup("kube-context")
		if f != nil {
			return f.Value.String()
		}
	}

	return ""
}

// fileExists reports whether the named file or directory exists.
func fileExists(filePath string) bool {
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}
