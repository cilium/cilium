// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/connrotation"

	"github.com/cilium/cilium/api/v1/models"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	slim_apiextclientsetscheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client/clientset/versioned/scheme"
	watcher_apiextclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-clientset"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slim_metav1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1beta1"
	watcher_client "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

var (
	// k8sCLI is the default client.
	k8sCLI = &K8sClient{}

	// k8sWatcherCLI is the client dedicated k8s structure watchers.
	k8sWatcherCLI = &K8sClient{}

	// k8sCiliumCLI is the default Cilium client.
	k8sCiliumCLI = &K8sCiliumClient{}

	// k8sCiliumCLI is the dedicated apiextensions client.
	k8sAPIExtCLI = &K8sAPIExtensionsClient{}

	// k8sAPIExtWatcherCLI is the client dedicated k8s structure watchers.
	k8sAPIExtWatcherCLI = &K8sAPIExtensionsClient{}
)

// Client returns the default Kubernetes client.
func Client() *K8sClient {
	return k8sCLI
}

// WatcherClient returns the client dedicated to K8s watchers.
func WatcherClient() *K8sClient {
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

// CreateConfig creates a client configuration based on the configured API
// server and Kubeconfig path
func CreateConfig() (*rest.Config, error) {
	return createConfig(GetAPIServerURL(), GetKubeconfigPath(), GetQPS(), GetBurst())
}

// CreateConfigFromAgentResponse creates a client configuration from a
// models.DaemonConfigurationResponse
func CreateConfigFromAgentResponse(resp *models.DaemonConfiguration) (*rest.Config, error) {
	return createConfig(resp.Status.K8sEndpoint, resp.Status.K8sConfiguration, GetQPS(), GetBurst())
}

// createClient creates a new client to access the Kubernetes API
func createClient(config *rest.Config, cs kubernetes.Interface) error {
	stop := make(chan struct{})
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	var err error
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
	return err
}

func createDefaultClient(c *rest.Config, httpClient *http.Client) (rest.Interface, error) {
	restConfig := *c
	restConfig.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`

	createdK8sClient, err := kubernetes.NewForConfigAndClient(&restConfig, httpClient)
	if err != nil {
		return nil, err
	}
	err = createClient(&restConfig, createdK8sClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCLI.Interface = createdK8sClient

	createK8sWatcherCli, err := watcher_client.NewForConfigAndClient(&restConfig, httpClient)
	if err != nil {
		return nil, err
	}

	k8sWatcherCLI.Interface = createK8sWatcherCli

	return createdK8sClient.RESTClient(), nil
}

func createDefaultCiliumClient(c *rest.Config, httpClient *http.Client) error {
	createdCiliumK8sClient, err := clientset.NewForConfigAndClient(c, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	k8sCiliumCLI.Interface = createdCiliumK8sClient

	return nil
}

func createAPIExtensionsClient(restConfig *rest.Config, httpClient *http.Client) error {
	c, err := apiextclientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create rest configuration for k8s CRD: %w", err)
	}

	k8sAPIExtCLI.Interface = c

	createK8sWatcherAPIExtCli, err := watcher_apiextclientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return err
	}

	k8sAPIExtWatcherCLI.Interface = createK8sWatcherAPIExtCli

	return nil
}

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
	cmdName := "cilium"
	if len(os.Args[0]) != 0 {
		cmdName = filepath.Base(os.Args[0])
	}
	userAgent := fmt.Sprintf("%s/%s", cmdName, version.Version)

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
	if userAgent != "" {
		config.UserAgent = userAgent
	}
	if qps != 0.0 {
		config.QPS = qps
	}
	if burst != 0 {
		config.Burst = burst
	}
}

func setDialer(config *rest.Config) func() {
	if option.Config.K8sHeartbeatTimeout == 0 {
		return func() {}
	}
	ctx := (&net.Dialer{
		Timeout:   option.Config.K8sHeartbeatTimeout,
		KeepAlive: option.Config.K8sHeartbeatTimeout,
	}).DialContext
	dialer := connrotation.NewDialer(ctx)
	config.Dial = dialer.DialContext
	return dialer.CloseAll
}

func runHeartbeat(heartBeat func(context.Context) error, timeout time.Duration, closeAllConns ...func()) {
	expireDate := time.Now().Add(-timeout)
	// Don't even perform a health check if we have received a successful
	// k8s event in the last 'timeout' duration
	if k8smetrics.LastSuccessInteraction.Time().After(expireDate) {
		return
	}

	done := make(chan error)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		// If we have reached up to this point to perform a heartbeat to
		// kube-apiserver then we should close the connections if we receive
		// any error at all except if we receive a http.StatusTooManyRequests
		// which means the server is overloaded and only for this reason we
		// will not close all connections.
		err := heartBeat(ctx)
		switch t := err.(type) {
		case *errors.StatusError:
			if t.ErrStatus.Code != http.StatusTooManyRequests {
				done <- err
			}
		default:
			done <- err
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
}

// isConnReady returns the err for the kube-system namespace get
func isConnReady(c kubernetes.Interface) error {
	_, err := c.CoreV1().Namespaces().Get(context.TODO(), "kube-system", metav1.GetOptions{})
	return err
}

func init() {
	// Register the metav1.Table and metav1.PartialObjectMetadata for the
	// apiextclientset.
	utilruntime.Must(slim_metav1.AddMetaToScheme(slim_apiextclientsetscheme.Scheme))
	utilruntime.Must(slim_metav1beta1.AddMetaToScheme(slim_apiextclientsetscheme.Scheme))
}
