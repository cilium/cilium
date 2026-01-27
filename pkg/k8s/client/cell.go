// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cilium/hive/cell"
	apiext_clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/connrotation"
	mcsapi_clientset "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned"

	"github.com/cilium/cilium/pkg/controller"
	cilium_clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	slim_clientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// client.Cell provides Clientset, a composition of clientsets to Kubernetes resources
// used by Cilium.
var Cell = cell.Module(
	"k8s-client",
	"Kubernetes Client",

	cell.Config(defaultSharedConfig),
	cell.Config(defaultClientParams),
	cell.Provide(NewClientConfig),
	cell.Provide(newClientset),

	cell.Invoke(registerMappingsUpdater),
)

// client.ClientBuilderCell provides a function to create a new composite Clientset,
// allowing a controller to use its own Clientset with a different user agent.
var ClientBuilderCell = cell.Module(
	"k8s-client-builder",
	"Kubernetes Client Builder",

	cell.Config(defaultSharedConfig),
	cell.Provide(NewClientConfig),
	cell.Provide(NewClientBuilder),
)

var (
	k8sHeartbeatControllerGroup = controller.NewGroup("k8s-heartbeat")
	connTimeout                 = time.Minute
	connRetryInterval           = 5 * time.Second
)

// Type aliases for the clientsets to avoid name collision on 'Clientset' when composing them.
type (
	MCSAPIClientset     = mcsapi_clientset.Clientset
	KubernetesClientset = kubernetes.Clientset
	SlimClientset       = slim_clientset.Clientset
	APIExtClientset     = apiext_clientset.Clientset
	CiliumClientset     = cilium_clientset.Clientset
)

// Clientset is a composition of the different client sets used by Cilium.
type Clientset interface {
	mcsapi_clientset.Interface
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

	// Config returns the configuration used to create this client.
	Config() Config

	// RestConfig returns the deep copy of rest configuration.
	RestConfig() *rest.Config
}

// compositeClientset implements the Clientset using real clients.
type compositeClientset struct {
	*MCSAPIClientset
	*KubernetesClientset
	*APIExtClientset
	*CiliumClientset
	ClientsetGetters

	controller        *controller.Manager
	slim              *SlimClientset
	config            Config
	logger            *slog.Logger
	closeAllConns     func()
	restConfigManager *restConfigManager
}

// ConfigureK8sClientsetDialer provides an optional extension point
// to configure the dialer used by the clientset.
type ConfigureK8sClientsetDialer interface {
	ConfigureK8sClientsetDialer(dialer *net.Dialer)
}

type compositeClientsetParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	Config    Config

	ConfigureK8sClientsetDialer ConfigureK8sClientsetDialer `optional:"true"`
}

func newClientset(params compositeClientsetParams) (Clientset, *restConfigManager, error) {
	return newClientsetForUserAgent(params, "")
}

func newClientsetForUserAgent(params compositeClientsetParams, name string) (Clientset, *restConfigManager, error) {
	if !params.Config.IsEnabled() {
		return &compositeClientset{config: params.Config}, nil, nil
	}

	client := compositeClientset{
		logger:     params.Logger,
		controller: controller.NewManager(),
		config:     params.Config,
	}

	var err error
	client.restConfigManager, err = restConfigManagerInit(params.Config, name, params.Logger)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s client rest configuration: %w", err)
	}
	rc := client.restConfigManager.getConfig()

	defaultCloseAllConns := params.setDialer(rc)

	httpClient, err := rest.HTTPClientFor(rc)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s REST client: %w", err)
	}

	// We are implementing the same logic as Kubelet, see
	// https://github.com/kubernetes/kubernetes/blob/v1.24.0-beta.0/cmd/kubelet/app/server.go#L852.
	if s := os.Getenv("DISABLE_HTTP2"); len(s) > 0 {
		client.closeAllConns = defaultCloseAllConns
	} else {
		client.closeAllConns = func() {
			utilnet.CloseIdleConnectionsFor(rc.Transport)
		}
	}

	// Slim and K8s clients use protobuf marshalling.
	rc.ContentConfig.ContentType = `application/vnd.kubernetes.protobuf`

	client.slim, err = slim_clientset.NewForConfigAndClient(rc, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create slim k8s client: %w", err)
	}

	client.APIExtClientset, err = apiext_clientset.NewForConfigAndClient(rc, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create apiext k8s client: %w", err)
	}

	client.MCSAPIClientset, err = mcsapi_clientset.NewForConfigAndClient(rc, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create mcsapi k8s client: %w", err)
	}

	client.KubernetesClientset, err = kubernetes.NewForConfigAndClient(rc, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s client: %w", err)
	}

	client.ClientsetGetters = ClientsetGetters{&client}

	// The cilium client uses JSON marshalling.
	rc.ContentConfig.ContentType = `application/json`
	client.CiliumClientset, err = cilium_clientset.NewForConfigAndClient(rc, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create cilium k8s client: %w", err)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: client.onStart,
		OnStop:  client.onStop,
	})

	return &client, client.restConfigManager, nil
}

func (c *compositeClientset) Slim() slim_clientset.Interface {
	return c.slim
}

func (c *compositeClientset) Discovery() discovery.DiscoveryInterface {
	return c.KubernetesClientset.Discovery()
}

func (c *compositeClientset) IsEnabled() bool {
	return c != nil && c.config.IsEnabled()
}

func (c *compositeClientset) Config() Config {
	return c.config
}

func (c *compositeClientset) RestConfig() *rest.Config {
	return c.restConfigManager.getConfig()
}

func (c *compositeClientset) onStart(startCtx cell.HookContext) error {
	if !c.IsEnabled() {
		return nil
	}

	if err := c.waitForConn(startCtx); err != nil {
		return err
	}
	c.startHeartbeat()

	// Update the global K8s clients, K8s version and the capabilities.
	if err := k8sversion.Update(c.logger, c, c.config.EnableK8sAPIDiscovery); err != nil {
		return err
	}

	if !k8sversion.Capabilities().MinimalVersionMet {
		return fmt.Errorf("k8s version (%v) is not meeting the minimal requirement (%v)",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	return nil
}

func (c *compositeClientset) onStop(stopCtx cell.HookContext) error {
	if c.IsEnabled() {
		c.controller.RemoveAllAndWait()
		c.closeAllConns()
	}
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
		// our case because the amount of data transferred is bigger than doing a Get of /readyz.
		// For this reason we have picked to perform a get on `/readyz` instead a get of a node.
		//
		// [0] https://github.com/kubernetes/kubernetes/blob/v1.17.3/pkg/kubelet/kubelet_node_status.go#L423
		res := restClient.Get().Resource("readyz").Do(ctx)
		return res.Error()
	}

	rotateAPIServer := func() {
		if c.restConfigManager.canRotateAPIServerURL() {
			c.restConfigManager.rotateAPIServerURL()
		}
	}

	c.controller.UpdateController("k8s-heartbeat",
		controller.ControllerParams{
			Group: k8sHeartbeatControllerGroup,
			DoFunc: func(context.Context) error {
				runHeartbeat(
					c.logger,
					heartBeat,
					timeout,
					c.closeAllConns,
					rotateAPIServer,
				)
				return nil
			},
			RunInterval: timeout,
		})
}

func (c *compositeClientset) waitForConn(ctx context.Context) error {
	stop := make(chan struct{})
	timeout := time.NewTimer(connTimeout)
	defer timeout.Stop()
	var err error
	wait.Until(func() {
	retry:
		c.logger.Info("Establishing connection to apiserver",
			logfields.IPAddr, c.restConfigManager.getConfig().Host,
		)
		err = isConnReady(c)
		if err == nil {
			close(stop)
			return
		}

		select {
		case <-ctx.Done():
		case <-timeout.C:
		default:
			if c.restConfigManager.canRotateAPIServerURL() {
				c.restConfigManager.rotateAPIServerURL()
				goto retry
			}
			return
		}

		c.logger.Error("Unable to contact k8s api-server",
			logfields.IPAddr, c.restConfigManager.getConfig().Host,
			logfields.Error, err,
		)
		close(stop)
	}, connRetryInterval, stop)
	if err == nil {
		c.logger.Info("Connected to apiserver")
	}
	return err
}

func (p *compositeClientsetParams) setDialer(restConfig *rest.Config) func() {
	cfg := p.Config
	innerDialer := &net.Dialer{
		Timeout:   cfg.K8sClientConnectionTimeout,
		KeepAlive: cfg.K8sClientConnectionKeepAlive,
	}
	if p.ConfigureK8sClientsetDialer != nil {
		p.ConfigureK8sClientsetDialer.ConfigureK8sClientsetDialer(innerDialer)
	}

	ctx := innerDialer.DialContext
	if cfg.K8sClientConnectionTimeout == 0 || cfg.K8sClientConnectionKeepAlive == 0 {
		restConfig.Dial = ctx
		return func() {}
	}
	dialer := connrotation.NewDialer(ctx)
	restConfig.Dial = dialer.DialContext
	return dialer.CloseAll
}

func runHeartbeat(logger *slog.Logger, heartBeat func(context.Context) error, timeout time.Duration, onFailure ...func()) {
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
		if err != nil {
			statusError := &k8sErrors.StatusError{}
			if !errors.As(err, &statusError) ||
				statusError.ErrStatus.Code != http.StatusTooManyRequests {
				done <- err
			}
		}
		close(done)
	}()

	select {
	case err := <-done:
		if err != nil {
			logger.Warn("Network status error received, restarting client connections", logfields.Error, err)
			for _, fn := range onFailure {
				fn()
			}
		}
	case <-ctx.Done():
		logger.Warn("Heartbeat timed out, restarting client connections")
		for _, fn := range onFailure {
			fn()
		}
	}
}

// isConnReady returns the err for the kube-system namespace get
func isConnReady(c kubernetes.Interface) error {
	_, err := c.CoreV1().Namespaces().Get(context.TODO(), "kube-system", metav1.GetOptions{})
	return err
}

type ClientBuilderFunc func(name string) (Clientset, error)

// NewClientBuilder returns a function that creates a new Clientset with the given
// name appended to the user agent, or returns an error if the Clientset cannot be
// created.
func NewClientBuilder(params compositeClientsetParams) ClientBuilderFunc {
	return func(name string) (Clientset, error) {
		c, _, err := newClientsetForUserAgent(params, name)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}
