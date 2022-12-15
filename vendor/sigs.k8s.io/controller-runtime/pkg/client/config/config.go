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

package config

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"
)

// KubeconfigFlagName is the name of the kubeconfig flag
const KubeconfigFlagName = "kubeconfig"

var (
	kubeconfig string
	log        = logf.RuntimeLog.WithName("client").WithName("config")
)

// init registers the "kubeconfig" flag to the default command line FlagSet.
// TODO: This should be removed, as it potentially leads to redefined flag errors for users, if they already
// have registered the "kubeconfig" flag to the command line FlagSet in other parts of their code.
func init() {
	RegisterFlags(flag.CommandLine)
}

// RegisterFlags registers flag variables to the given FlagSet if not already registered.
// It uses the default command line FlagSet, if none is provided. Currently, it only registers the kubeconfig flag.
func RegisterFlags(fs *flag.FlagSet) {
	if fs == nil {
		fs = flag.CommandLine
	}
	if f := fs.Lookup(KubeconfigFlagName); f != nil {
		kubeconfig = f.Value.String()
	} else {
		fs.StringVar(&kubeconfig, KubeconfigFlagName, "", "Paths to a kubeconfig. Only required if out-of-cluster.")
	}
}

// GetConfig creates a *rest.Config for talking to a Kubernetes API server.
// If --kubeconfig is set, will use the kubeconfig file at that location.  Otherwise will assume running
// in cluster and use the cluster provided kubeconfig.
//
// It also applies saner defaults for QPS and burst based on the Kubernetes
// controller manager defaults (20 QPS, 30 burst)
//
// Config precedence:
//
// * --kubeconfig flag pointing at a file
//
// * KUBECONFIG environment variable pointing at a file
//
// * In-cluster config if running in cluster
//
// * $HOME/.kube/config if exists.
func GetConfig() (*rest.Config, error) {
	return GetConfigWithContext("")
}

// GetConfigWithContext creates a *rest.Config for talking to a Kubernetes API server with a specific context.
// If --kubeconfig is set, will use the kubeconfig file at that location.  Otherwise will assume running
// in cluster and use the cluster provided kubeconfig.
//
// It also applies saner defaults for QPS and burst based on the Kubernetes
// controller manager defaults (20 QPS, 30 burst)
//
// Config precedence:
//
// * --kubeconfig flag pointing at a file
//
// * KUBECONFIG environment variable pointing at a file
//
// * In-cluster config if running in cluster
//
// * $HOME/.kube/config if exists.
func GetConfigWithContext(context string) (*rest.Config, error) {
	cfg, err := loadConfig(context)
	if err != nil {
		return nil, err
	}

	if cfg.QPS == 0.0 {
		cfg.QPS = 20.0
		cfg.Burst = 30.0
	}

	return cfg, nil
}

// loadInClusterConfig is a function used to load the in-cluster
// Kubernetes client config. This variable makes is possible to
// test the precedence of loading the config.
var loadInClusterConfig = rest.InClusterConfig

// loadConfig loads a REST Config as per the rules specified in GetConfig.
func loadConfig(context string) (config *rest.Config, configErr error) {
	// If a flag is specified with the config location, use that
	if len(kubeconfig) > 0 {
		return loadConfigWithContext("", &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}, context)
	}

	// If the recommended kubeconfig env variable is not specified,
	// try the in-cluster config.
	kubeconfigPath := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if len(kubeconfigPath) == 0 {
		c, err := loadInClusterConfig()
		if err == nil {
			return c, nil
		}

		defer func() {
			if configErr != nil {
				log.Error(err, "unable to load in-cluster config")
			}
		}()
	}

	// If the recommended kubeconfig env variable is set, or there
	// is no in-cluster config, try the default recommended locations.
	//
	// NOTE: For default config file locations, upstream only checks
	// $HOME for the user's home directory, but we can also try
	// os/user.HomeDir when $HOME is unset.
	//
	// TODO(jlanford): could this be done upstream?
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if _, ok := os.LookupEnv("HOME"); !ok {
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("could not get current user: %w", err)
		}
		loadingRules.Precedence = append(loadingRules.Precedence, filepath.Join(u.HomeDir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName))
	}

	return loadConfigWithContext("", loadingRules, context)
}

func loadConfigWithContext(apiServerURL string, loader clientcmd.ClientConfigLoader, context string) (*rest.Config, error) {
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loader,
		&clientcmd.ConfigOverrides{
			ClusterInfo: clientcmdapi.Cluster{
				Server: apiServerURL,
			},
			CurrentContext: context,
		}).ClientConfig()
}

// GetConfigOrDie creates a *rest.Config for talking to a Kubernetes apiserver.
// If --kubeconfig is set, will use the kubeconfig file at that location.  Otherwise will assume running
// in cluster and use the cluster provided kubeconfig.
//
// Will log an error and exit if there is an error creating the rest.Config.
func GetConfigOrDie() *rest.Config {
	config, err := GetConfig()
	if err != nil {
		log.Error(err, "unable to get kubeconfig")
		os.Exit(1)
	}
	return config
}
