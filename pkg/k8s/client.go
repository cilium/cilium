// Copyright 2016-2020 Authors of Cilium
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
	"context"
	goerrors "errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/connrotation"
)

var (
	// ErrNilNode is returned when the Kubernetes API server has returned a nil node
	ErrNilNode = goerrors.New("API server returned nil node")

	// k8sCli is the default client.
	k8sCli = &K8sClient{}

	// k8sCiliumCli is the default Cilium client.
	k8sCiliumCli = &K8sCiliumClient{}
)

// createConfig creates a rest.Config for connecting to k8s api-server.
//
// The precedence of the configuration selection is the following:
// 1. kubeCfgPath
// 2. apiServerURL (https if specified)
// 3. rest.InClusterConfig().
func createConfig(apiServerURL, kubeCfgPath string, qps float32, burst int) (*rest.Config, error) {
	var (
		config *rest.Config
		err    error
	)
	userAgent := fmt.Sprintf("Cilium %s", version.Version)

	switch {
	// If the apiServerURL and the kubeCfgPath are empty then we can try getting
	// the rest.Config from the InClusterConfig
	case apiServerURL == "" && kubeCfgPath == "":
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
	case kubeCfgPath != "":
		if config, err = clientcmd.BuildConfigFromFlags("", kubeCfgPath); err != nil {
			return nil, err
		}
	case strings.HasPrefix(apiServerURL, "https://"):
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
		config.Host = apiServerURL
	default:
		config = &rest.Config{Host: apiServerURL, UserAgent: userAgent}
	}

	setConfig(config, userAgent, qps, burst)
	return config, nil
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
	return createConfig(GetAPIServerURL(), GetKubeconfigPath(), GetQPS(), GetBurst())
}

func setDialer(config *rest.Config) func() {
	context := (&net.Dialer{
		Timeout:   option.Config.K8sHeartbeatTimeout,
		KeepAlive: option.Config.K8sHeartbeatTimeout,
	}).DialContext
	dialer := connrotation.NewDialer(context)
	config.Dial = dialer.DialContext
	return dialer.CloseAll
}

func runHeartbeat(client rest.Interface, closeAllConns []func(), stop chan struct{}) {
	timeout := option.Config.K8sHeartbeatTimeout
	go wait.Until(func() {
		done := make(chan error)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		go func() {
			// Kubernetes does a get node of the node that kubelet is running [0]. This seems excessive in
			// our case because the amount of data transferred is bigger than doing a Get of /healthz.
			// For this reason we have picked to perform a get on `/healthz` instead a get of a node.
			//
			// [0] https://github.com/kubernetes/kubernetes/blob/v1.17.3/pkg/kubelet/kubelet_node_status.go#L423
			res := client.Get().Resource("healthz").Do(ctx)
			switch t := res.Error().(type) {
			case *errors.StatusError:
				switch t.ErrStatus.Code {
				case http.StatusGatewayTimeout,
					http.StatusRequestTimeout,
					http.StatusBadGateway:
					done <- t
				}
			}

			close(done)
		}()

		select {
		case err := <-done:
			if err != nil {
				log.WithError(err).Warn("Network status error received, restarting client connections")
				for _, fn := range closeAllConns {
					fn()
				}
			}
		case <-ctx.Done():
			log.Warn("Heartbeat timed out, restarting client connections")
			for _, fn := range closeAllConns {
				fn()
			}
		}
	}, timeout, stop)
}

// CreateClient creates a new client to access the Kubernetes API
func CreateClient(config *rest.Config) (*kubernetes.Clientset, func(), error) {
	closeAllConns := setDialer(config)
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
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
	return cs, closeAllConns, err
}

// isConnReady returns the err for the kube-system namespace get
func isConnReady(c kubernetes.Interface) error {
	_, err := c.CoreV1().Namespaces().Get(context.TODO(), "kube-system", metav1.GetOptions{})
	return err
}

// Client returns the default Kubernetes client.
func Client() *K8sClient {
	return k8sCli
}

func createDefaultClient() (rest.Interface, func(), error) {
	restConfig, err := CreateConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}
	restConfig.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`

	createdK8sClient, closeAllConns, err := CreateClient(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCli.Interface = createdK8sClient

	return createdK8sClient.RESTClient(), closeAllConns, nil
}

// CiliumClient returns the default Cilium Kubernetes client.
func CiliumClient() *K8sCiliumClient {
	return k8sCiliumCli
}

func createDefaultCiliumClient() (func(), error) {
	restConfig, err := CreateConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}

	closeAllConns := setDialer(restConfig)
	createdCiliumK8sClient, err := clientset.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCiliumCli.Interface = createdCiliumK8sClient

	return closeAllConns, nil
}
