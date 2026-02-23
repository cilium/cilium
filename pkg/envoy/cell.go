// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	config "github.com/cilium/cilium/pkg/envoy/config"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/shortener"
	"github.com/cilium/cilium/pkg/time"
)

// Cell initializes and manages the Envoy proxy and its control-plane components like xDS- and accesslog server.
// It is used to provide support for Ingress, GatewayAPI and L7 network policies (e.g. HTTP).
var Cell = cell.Module(
	"envoy-proxy",
	"Envoy proxy and control-plane",

	metrics.Metric(xds.NewXDSMetric),

	cell.Config(config.ProxyConfig{}),
	cell.Config(config.SecretSyncConfig{}),
	cell.Provide(newEnvoyXDSServer),
	cell.Provide(newEnvoyAdminClient),
	cell.Provide(envoypolicy.NewEnvoyL7RulesTranslator),
	cell.ProvidePrivate(newEnvoyAccessLogServer),
	cell.ProvidePrivate(newLocalEndpointStore),
	cell.ProvidePrivate(newArtifactCopier),
	cell.Invoke(registerEnvoyVersionCheck),
	cell.Invoke(registerSecretSyncer),
)

type xdsServerParams struct {
	cell.In

	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Logger             *slog.Logger
	IPCache            *ipcache.IPCache
	RestorerPromise    promise.Promise[endpointstate.Restorer]
	LocalEndpointStore *LocalEndpointStore

	EnvoyProxyConfig config.ProxyConfig

	// Depend on access log server to enforce init order.
	// This ensures that the access log server is ready before it gets used by the
	// Cilium Envoy filter after receiving the resources via xDS server.
	AccessLogServer *AccessLogServer

	// Depend on ArtifactCopier to enforce init order and ensure that the additional artifacts are copied
	// before starting the xDS server (and starting to configure Envoy).
	ArtifactCopier *ArtifactCopier

	SecretManager certificatemanager.SecretManager
	Metrics       *xds.XDSMetrics
}

func newEnvoyXDSServer(params xdsServerParams) (XDSServer, error) {
	// Override the default value before bootstrap is created for embedded envoy, or
	// the xDS ConfigSource is used for CEC/CCEC.
	CiliumXDSConfigSource.InitialFetchTimeout.Seconds = int64(params.EnvoyProxyConfig.ProxyInitialFetchTimeout)

	xdsServer := newXDSServer(
		params.Logger,
		params.RestorerPromise,
		params.IPCache,
		params.LocalEndpointStore,
		xdsServerConfig{
			envoySocketDir:                GetSocketDir(option.Config.RunDir),
			proxyGID:                      int(params.EnvoyProxyConfig.ProxyGID),
			httpRequestTimeout:            int(params.EnvoyProxyConfig.HTTPRequestTimeout),
			httpIdleTimeout:               params.EnvoyProxyConfig.ProxyIdleTimeoutSeconds,
			httpMaxGRPCTimeout:            int(params.EnvoyProxyConfig.HTTPMaxGRPCTimeout),
			httpRetryCount:                int(params.EnvoyProxyConfig.HTTPRetryCount),
			httpRetryTimeout:              int(params.EnvoyProxyConfig.HTTPRetryTimeout),
			httpStreamIdleTimeout:         int(params.EnvoyProxyConfig.HTTPStreamIdleTimeout),
			httpNormalizePath:             params.EnvoyProxyConfig.HTTPNormalizePath,
			useFullTLSContext:             params.EnvoyProxyConfig.UseFullTLSContext,
			useSDS:                        params.SecretManager.PolicySecretSyncEnabled(),
			proxyXffNumTrustedHopsIngress: params.EnvoyProxyConfig.ProxyXffNumTrustedHopsIngress,
			proxyXffNumTrustedHopsEgress:  params.EnvoyProxyConfig.ProxyXffNumTrustedHopsEgress,
			policyRestoreTimeout:          params.EnvoyProxyConfig.EnvoyPolicyRestoreTimeout,
			metrics:                       params.Metrics,
			httpLingerConfig:              params.EnvoyProxyConfig.EnvoyHTTPUpstreamLingerTimeout,
		},
		params.SecretManager)

	if !option.Config.EnableL7Proxy {
		params.Logger.Debug("L7 proxies are disabled - not starting Envoy xDS server")
		return xdsServer, nil
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			params.JobGroup.Add(job.OneShot("xds-server", func(ctx context.Context, _ cell.Health) error {
				return xdsServer.start(ctx)
			}, job.WithShutdown()))
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			xdsServer.stop()
			return nil
		},
	})

	if !option.Config.ExternalEnvoyProxy {
		return &onDemandXdsStarter{
			XDSServer:                      xdsServer,
			logger:                         params.Logger,
			runDir:                         option.Config.RunDir,
			envoyLogPath:                   params.EnvoyProxyConfig.EnvoyLog,
			envoyDefaultLogLevel:           params.EnvoyProxyConfig.EnvoyDefaultLogLevel,
			envoyBaseID:                    params.EnvoyProxyConfig.EnvoyBaseID,
			keepCapNetBindService:          params.EnvoyProxyConfig.EnvoyKeepCapNetbindservice,
			metricsListenerPort:            params.EnvoyProxyConfig.ProxyPrometheusPort,
			adminListenerPort:              params.EnvoyProxyConfig.ProxyAdminPort,
			connectTimeout:                 int64(params.EnvoyProxyConfig.ProxyConnectTimeout),
			maxActiveDownstreamConnections: params.EnvoyProxyConfig.ProxyMaxActiveDownstreamConnections,
			maxRequestsPerConnection:       uint32(params.EnvoyProxyConfig.ProxyMaxRequestsPerConnection),
			maxConnectionDuration:          time.Duration(params.EnvoyProxyConfig.ProxyMaxConnectionDurationSeconds) * time.Second,
			idleTimeout:                    time.Duration(params.EnvoyProxyConfig.ProxyIdleTimeoutSeconds) * time.Second,
			maxConcurrentRetries:           params.EnvoyProxyConfig.ProxyMaxConcurrentRetries,
			maxConnections:                 params.EnvoyProxyConfig.ProxyClusterMaxConnections,
			maxRequests:                    params.EnvoyProxyConfig.ProxyClusterMaxRequests,
		}, nil
	}

	return xdsServer, nil
}

func newEnvoyAdminClient(logger *slog.Logger, envoyProxyConfig config.ProxyConfig) *EnvoyAdminClient {
	return NewEnvoyAdminClientForSocket(logger, GetSocketDir(option.Config.RunDir), envoyProxyConfig.EnvoyDefaultLogLevel)
}

type accessLogServerParams struct {
	cell.In

	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Logger             *slog.Logger
	AccessLogger       accesslog.ProxyAccessLogger
	LocalEndpointStore *LocalEndpointStore
	EnvoyProxyConfig   config.ProxyConfig
}

func newEnvoyAccessLogServer(params accessLogServerParams) *AccessLogServer {
	if !option.Config.EnableL7Proxy {
		params.Logger.Debug("L7 proxies are disabled - not starting Envoy AccessLog server")
		return nil
	}

	accessLogServer := newAccessLogServer(
		params.Logger,
		params.AccessLogger,
		GetSocketDir(option.Config.RunDir),
		params.EnvoyProxyConfig.ProxyGID,
		params.LocalEndpointStore,
		params.EnvoyProxyConfig.EnvoyAccessLogBufferSize,
	)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			params.JobGroup.Add(job.OneShot("accesslog-server", func(ctx context.Context, _ cell.Health) error {
				return accessLogServer.start(ctx)
			}, job.WithShutdown()))
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			accessLogServer.stop()
			return nil
		},
	})

	return accessLogServer
}

type versionCheckParams struct {
	cell.In

	Logger           *slog.Logger
	JobGroup         job.Group
	EnvoyProxyConfig config.ProxyConfig
	EnvoyAdminClient *EnvoyAdminClient
}

func registerEnvoyVersionCheck(params versionCheckParams) {
	if !option.Config.EnableL7Proxy || params.EnvoyProxyConfig.DisableEnvoyVersionCheck {
		return
	}

	checker := &envoyVersionChecker{
		logger:        params.Logger,
		externalEnvoy: option.Config.ExternalEnvoyProxy,
		adminClient:   params.EnvoyAdminClient,
	}

	// To prevent agent restarts in case the Envoy DaemonSet isn't ready yet,
	// version check is performed periodically and any errors are logged
	// and reported via health reporter.
	var previousError error
	params.JobGroup.Add(job.Timer("version-check", func(_ context.Context) error {
		if err := checker.checkEnvoyVersion(); err != nil {
			// We only log it as an error if it happens at least twice,
			// as it is expected that during upgrade of Cilium, the Envoy version might differ
			// for a short period of time.
			logger := params.Logger.Info
			if previousError != nil {
				logger = params.Logger.Error
			}
			logger("Envoy: Version check failed", logfields.Error, err)
			previousError = err
			return err
		}

		previousError = nil
		return nil
	}, 2*time.Minute))
}

func newLocalEndpointStore() *LocalEndpointStore {
	return &LocalEndpointStore{
		networkPolicyEndpoints: make(map[string]endpoint.EndpointUpdater),
	}
}

func newArtifactCopier(lifecycle cell.Lifecycle, logger *slog.Logger) *ArtifactCopier {
	artifactCopier := &ArtifactCopier{
		logger:     logger,
		sourcePath: "/envoy-artifacts",
		targetPath: filepath.Join(option.Config.RunDir, "envoy", "artifacts"),
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			if err := artifactCopier.Copy(); err != nil {
				return fmt.Errorf("failed to copy artifacts to envoy: %w", err)
			}
			return nil
		},
	})

	return artifactCopier
}

type syncerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	K8sClientset client.Clientset

	Config        config.SecretSyncConfig
	XdsServer     XDSServer
	SecretManager certificatemanager.SecretManager

	MetricsProvider workqueue.MetricsProvider
}

func registerSecretSyncer(params syncerParams) error {
	if !params.K8sClientset.IsEnabled() || !option.Config.EnableL7Proxy {
		return nil
	}

	// Create a Secret Resource for each namespace.
	// The Cilium Agent only has permissions on the specific namespaces.
	// Note that the different features can use the same namespace for
	// their TLS secrets.
	namespaces := map[string]struct{}{}

	for namespace, cond := range map[string]func() bool{
		params.Config.EnvoySecretsNamespace:           func() bool { return option.Config.EnableEnvoyConfig },
		params.Config.IngressSecretsNamespace:         func() bool { return params.Config.EnableIngressController },
		params.Config.GatewayAPISecretsNamespace:      func() bool { return params.Config.EnableGatewayAPI },
		params.SecretManager.GetSecretSyncNamespace(): func() bool { return params.SecretManager.SecretsOnlyFromSecretsNamespace() },
	} {
		if len(namespace) > 0 && cond() {
			namespaces[namespace] = struct{}{}
		}
	}

	if len(namespaces) == 0 {
		return nil
	}

	secretSyncerLogger := params.Logger.With(logfields.Controller, "secretSyncer")

	secretSyncer := newSecretSyncer(secretSyncerLogger, params.XdsServer)

	secretSyncerLogger.Debug("Watching namespaces for secrets",
		logfields.K8sNamespace, namespaces,
	)

	for ns := range namespaces {
		params.JobGroup.Add(job.Observer(
			shortener.ShortenK8sResourceName(fmt.Sprintf("k8s-secrets-resource-events-%s", ns)),
			secretSyncer.handleSecretEvent,
			newK8sSecretResource(params.Lifecycle, params.K8sClientset, params.MetricsProvider, ns),
		))
	}

	return nil
}

func newK8sSecretResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, namespace string) resource.Resource[*slim_corev1.Secret] {
	if !cs.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.SecretList](cs.Slim().CoreV1().Secrets(namespace)),
	)

	return resource.New[*slim_corev1.Secret](lc, lw, mp, resource.WithMetric("Secret"))
}
