// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	apiext_clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiext_fake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/connrotation"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	slim_apiextclientsetscheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client/clientset/versioned/scheme"
	slim_apiext_clientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-clientset"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slim_metav1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1beta1"
	slim_clientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/version"
)

// client.Cell provides Clientset, a composition of clientsets to Kubernetes resources
// used by Cilium.
var Cell = cell.Module(
	"k8s-client",
	"Kubernetes Client",

	cell.Config(defaultConfig),
	cell.Provide(newClientset),
)

// Type aliases for the clientsets to avoid name collision on 'Clientset' when composing them.
type (
	KubernetesClientset = kubernetes.Clientset
	SlimClientset       = slim_clientset.Clientset
	APIExtClientset     = slim_apiext_clientset.Clientset
	CiliumClientset     = cilium_clientset.Clientset
)

// Clientset is a composition of the different client sets used by Cilium.
type Clientset interface {
	kubernetes.Interface
	apiext_clientset.Interface
	cilium_clientset.Interface
	Getters

	// Slim returns the slim client, which contains some of the same APIs as the
	// normal kubernetes client, but with slimmed down messages to reduce memory
	// usage. Prefer the slim version when caching messages.
	Slim() slim_clientset.Interface

	// IsEnabled returns true if Kubernetes support is enabled and the
	// clientset can be used.
	IsEnabled() bool

	// Disable disables the client. Panics if called after the clientset has been
	// started.
	Disable()

	// Config returns the configuration used to create this client.
	Config() Config

	// RestConfig returns the deep copy of rest configuration.
	RestConfig() *rest.Config
}

// compositeClientset implements the Clientset using real clients.
type compositeClientset struct {
	started  bool
	disabled bool

	*KubernetesClientset
	*APIExtClientset
	*CiliumClientset
	clientsetGetters

	controller    *controller.Manager
	slim          *SlimClientset
	config        Config
	log           logrus.FieldLogger
	closeAllConns func()
	restConfig    *rest.Config
}

func newClientset(lc hive.Lifecycle, log logrus.FieldLogger, cfg Config) (Clientset, error) {
	if !cfg.isEnabled() {
		return &compositeClientset{disabled: true}, nil
	}

	if cfg.K8sAPIServer != "" &&
		!strings.HasPrefix(cfg.K8sAPIServer, "http") {
		cfg.K8sAPIServer = "http://" + cfg.K8sAPIServer // default to HTTP
	}

	client := compositeClientset{
		log:        log,
		controller: controller.NewManager(),
		config:     cfg,
	}

	restConfig, err := createConfig(cfg.K8sAPIServer, cfg.K8sKubeConfigPath, cfg.K8sClientQPS, cfg.K8sClientBurst)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client rest configuration: %w", err)
	}
	client.restConfig = restConfig
	defaultCloseAllConns := setDialer(cfg, restConfig)

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s REST client: %w", err)
	}

	// We are implementing the same logic as Kubelet, see
	// https://github.com/kubernetes/kubernetes/blob/v1.24.0-beta.0/cmd/kubelet/app/server.go#L852.
	if s := os.Getenv("DISABLE_HTTP2"); len(s) > 0 {
		client.closeAllConns = defaultCloseAllConns
	} else {
		client.closeAllConns = func() {
			utilnet.CloseIdleConnectionsFor(restConfig.Transport)
		}
	}

	// Slim and K8s clients use protobuf marshalling.
	restConfig.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`

	client.slim, err = slim_clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create slim k8s client: %w", err)
	}

	client.APIExtClientset, err = slim_apiext_clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create apiext k8s client: %w", err)
	}

	client.KubernetesClientset, err = kubernetes.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client: %w", err)
	}

	client.clientsetGetters = clientsetGetters{&client}

	// The cilium client uses JSON marshalling.
	restConfig.ContentConfig.ContentType = `application/json`
	client.CiliumClientset, err = cilium_clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create cilium k8s client: %w", err)
	}

	lc.Append(hive.Hook{
		OnStart: client.onStart,
		OnStop:  client.onStop,
	})

	return &client, nil
}

func (c *compositeClientset) Slim() slim_clientset.Interface {
	return c.slim
}

func (c *compositeClientset) Discovery() discovery.DiscoveryInterface {
	return c.KubernetesClientset.Discovery()
}

func (c *compositeClientset) IsEnabled() bool {
	return c != nil && c.config.isEnabled() && !c.disabled
}

func (c *compositeClientset) Disable() {
	if c.started {
		panic("Clientset.Disable() called after it had been started")
	}
	c.disabled = true
}

func (c *compositeClientset) Config() Config {
	return c.config
}

func (c *compositeClientset) RestConfig() *rest.Config {
	return rest.CopyConfig(c.restConfig)
}

func (c *compositeClientset) onStart(startCtx hive.HookContext) error {
	if !c.IsEnabled() {
		return nil
	}

	if err := c.waitForConn(startCtx); err != nil {
		return err
	}
	c.startHeartbeat()

	// Update the global K8s clients, K8s version and the capabilities.
	if err := k8sversion.Update(c, c.config.EnableK8sAPIDiscovery); err != nil {
		return err
	}

	if !k8sversion.Capabilities().MinimalVersionMet {
		return fmt.Errorf("k8s version (%v) is not meeting the minimal requirement (%v)",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	c.started = true

	return nil
}

func (c *compositeClientset) onStop(stopCtx hive.HookContext) error {
	if c.IsEnabled() {
		c.controller.RemoveAllAndWait()
		c.closeAllConns()
	}
	c.started = false
	return nil
}

func (c *compositeClientset) startHeartbeat() {
	restClient := c.KubernetesClientset.RESTClient()

	timeout := c.config.K8sHeartbeatTimeout
	if timeout == 0 {
		return
	}

	heartBeat := func(ctx context.Context) error {
		// Kubernetes does a get node of the node that kubelet is running [0]. This seems excessive in
		// our case because the amount of data transferred is bigger than doing a Get of /healthz.
		// For this reason we have picked to perform a get on `/healthz` instead a get of a node.
		//
		// [0] https://github.com/kubernetes/kubernetes/blob/v1.17.3/pkg/kubelet/kubelet_node_status.go#L423
		res := restClient.Get().Resource("healthz").Do(ctx)
		return res.Error()
	}

	c.controller.UpdateController("k8s-heartbeat",
		controller.ControllerParams{
			DoFunc: func(context.Context) error {
				runHeartbeat(
					c.log,
					heartBeat,
					timeout,
					c.closeAllConns,
				)
				return nil
			},
			RunInterval: timeout,
		})
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

func (c *compositeClientset) waitForConn(ctx context.Context) error {
	stop := make(chan struct{})
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	var err error
	wait.Until(func() {
		c.log.WithField("host", c.restConfig.Host).Info("Establishing connection to apiserver")
		err = isConnReady(c)
		if err == nil {
			close(stop)
			return
		}

		select {
		case <-ctx.Done():
		case <-timeout.C:
		default:
			return
		}

		c.log.WithError(err).WithField(logfields.IPAddr, c.restConfig.Host).Error("Unable to contact k8s api-server")
		close(stop)
	}, 5*time.Second, stop)
	if err == nil {
		c.log.Info("Connected to apiserver")
	}
	return err
}

func setDialer(cfg Config, restConfig *rest.Config) func() {
	if cfg.K8sHeartbeatTimeout == 0 {
		return func() {}
	}
	ctx := (&net.Dialer{
		Timeout:   cfg.K8sHeartbeatTimeout,
		KeepAlive: cfg.K8sHeartbeatTimeout,
	}).DialContext
	dialer := connrotation.NewDialer(ctx)
	restConfig.Dial = dialer.DialContext
	return dialer.CloseAll
}

func runHeartbeat(log logrus.FieldLogger, heartBeat func(context.Context) error, timeout time.Duration, closeAllConns ...func()) {
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

var FakeClientCell = cell.Provide(NewFakeClientset)

type (
	KubernetesFakeClientset = fake.Clientset
	SlimFakeClientset       = slim_fake.Clientset
	CiliumFakeClientset     = cilium_fake.Clientset
	APIExtFakeClientset     = apiext_fake.Clientset
)

type FakeClientset struct {
	disabled bool

	*KubernetesFakeClientset
	*CiliumFakeClientset
	*APIExtFakeClientset
	clientsetGetters

	SlimFakeClientset *SlimFakeClientset

	enabled bool
}

var _ Clientset = &FakeClientset{}

func (c *FakeClientset) Slim() slim_clientset.Interface {
	return c.SlimFakeClientset
}

func (c *FakeClientset) Discovery() discovery.DiscoveryInterface {
	return c.KubernetesFakeClientset.Discovery()
}

func (c *FakeClientset) IsEnabled() bool {
	return !c.disabled
}

func (c *FakeClientset) Disable() {
	c.disabled = true
}

func (c *FakeClientset) Config() Config {
	return Config{}
}

func (c *FakeClientset) RestConfig() *rest.Config {
	return &rest.Config{}
}

func NewFakeClientset() (*FakeClientset, Clientset) {
	client := FakeClientset{
		SlimFakeClientset:       slim_fake.NewSimpleClientset(),
		CiliumFakeClientset:     cilium_fake.NewSimpleClientset(),
		APIExtFakeClientset:     apiext_fake.NewSimpleClientset(),
		KubernetesFakeClientset: fake.NewSimpleClientset(),
		enabled:                 true,
	}
	client.clientsetGetters = clientsetGetters{&client}
	return &client, &client
}

type standaloneLifecycle struct {
	hooks []hive.HookInterface
}

func (s *standaloneLifecycle) Append(hook hive.HookInterface) {
	s.hooks = append(s.hooks, hook)
}

// NewStandaloneClientset creates a clientset outside hive. To be removed once
// remaining uses of k8s.Init()/k8s.Client()/etc. have been converted.
func NewStandaloneClientset(cfg Config) (Clientset, error) {
	log := logging.DefaultLogger
	lc := &standaloneLifecycle{}

	clientset, err := newClientset(lc, log, cfg)
	if err != nil {
		return nil, err
	}

	for _, hook := range lc.hooks {
		if err := hook.Start(context.Background()); err != nil {
			return nil, err
		}
	}

	return clientset, err
}

func init() {
	// Register the metav1.Table and metav1.PartialObjectMetadata for the
	// apiextclientset.
	utilruntime.Must(slim_metav1.AddMetaToScheme(slim_apiextclientsetscheme.Scheme))
	utilruntime.Must(slim_metav1beta1.AddMetaToScheme(slim_apiextclientsetscheme.Scheme))
}
