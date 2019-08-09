// Copyright 2016-2019 Authors of Cilium
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
	goerrors "errors"
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/version"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// ErrNilNode is returned when the Kubernetes API server has returned a nil node
	ErrNilNode = goerrors.New("API server returned nil node")

	// k8sCli is the default client.
	k8sCli = &K8sClient{}

	// k8sCiliumCli is the default Cilium client.
	k8sCiliumCli = &K8sCiliumClient{}
)

// CreateConfig creates a rest.Config for a given endpoint using a kubeconfig file.
func createConfig(endpoint, kubeCfgPath string, qps float32, burst int) (*rest.Config, error) {
	userAgent := fmt.Sprintf("Cilium %s", version.Version)

	// If the endpoint and the kubeCfgPath are empty then we can try getting
	// the rest.Config from the InClusterConfig
	if endpoint == "" && kubeCfgPath == "" {
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		setConfig(config, userAgent, qps, burst)
		return config, nil
	}

	if kubeCfgPath != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeCfgPath)
		if err != nil {
			return nil, err
		}
		setConfig(config, userAgent, qps, burst)
		return config, nil
	}

	config := &rest.Config{Host: endpoint, UserAgent: userAgent}
	setConfig(config, userAgent, qps, burst)
	err := rest.SetKubernetesDefaults(config)

	return config, err
}

func setConfig(config *rest.Config, userAgent string, qps float32, burst int) {
	if config.UserAgent != "" {
		config.UserAgent = userAgent
	}
	if qps != 0.0 {
		config.QPS = qps
	}
	if burst != 0 {
		config.Burst = burst
	}
}

// CreateConfigFromAgentResponse creates a client configuration from a
// models.DaemonConfigurationResponse
func CreateConfigFromAgentResponse(resp *models.DaemonConfiguration) (*rest.Config, error) {
	return createConfig(resp.Status.K8sEndpoint, resp.Status.K8sConfiguration, GetQPS(), GetBurst())
}

// CreateConfig creates a client configuration based on the configured API
// server and Kubeconfig path
func CreateConfig() (*rest.Config, error) {
	return createConfig(GetAPIServer(), GetKubeconfigPath(), GetQPS(), GetBurst())
}

// CreateClient creates a new client to access the Kubernetes API
func CreateClient(config *rest.Config) (*kubernetes.Clientset, error) {
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	wait.Until(func() {
		// FIXME: Use config.String() when we rebase to latest go-client
		log.WithField("host", config.Host).Info("Establishing connection to apiserver")
		err = isConnReady(cs)
		if err == nil {
			close(stop)
			return
		}
		select {
		case <-timeout.C:
			log.WithError(err).WithField(logfields.IPAddr, config.Host).Error("Unable to contact k8s api-server")
			close(stop)
		default:
		}
	}, 5*time.Second, stop)
	if err == nil {
		log.Info("Connected to apiserver")
	}
	return cs, err
}

// isConnReady returns the err for the kube-system namespace get
func isConnReady(c *kubernetes.Clientset) error {
	_, err := c.CoreV1().Namespaces().Get("kube-system", metav1.GetOptions{})
	return err
}

// Client returns the default Kubernetes client.
func Client() *K8sClient {
	return k8sCli
}

func createDefaultClient() error {
	restConfig, err := CreateConfig()
	if err != nil {
		return fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}
	restConfig.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`

	createdK8sClient, err := CreateClient(restConfig)
	if err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCli.Interface = createdK8sClient

	return nil
}

// CiliumClient returns the default Cilium Kubernetes client.
func CiliumClient() *K8sCiliumClient {
	return k8sCiliumCli
}

func createDefaultCiliumClient() error {
	restConfig, err := CreateConfig()
	if err != nil {
		return fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}

	createdCiliumK8sClient, err := clientset.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCiliumCli.Interface = createdCiliumK8sClient

	return nil
}
