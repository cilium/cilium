// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime/pprof"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
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

	cell.Config(ProxyConfig{}),
	cell.Config(secretSyncConfig{}),
	cell.Provide(newEnvoyXDSServer),
	cell.Provide(newEnvoyAdminClient),
	cell.Provide(envoypolicy.NewEnvoyL7RulesTranslator),
	cell.ProvidePrivate(newEnvoyAccessLogServer),
	cell.ProvidePrivate(newLocalEndpointStore),
	cell.ProvidePrivate(newArtifactCopier),
	cell.Invoke(registerEnvoyVersionCheck),
	cell.Invoke(registerSecretSyncer),
)

type ProxyConfig struct {
	DisableEnvoyVersionCheck          bool
	ProxyPrometheusPort               int
	ProxyAdminPort                    int
	EnvoyLog                          string
	EnvoyAccessLogBufferSize          uint
	EnvoyDefaultLogLevel              string
	EnvoyBaseID                       uint64
	EnvoyKeepCapNetbindservice        bool
	ProxyConnectTimeout               uint
	ProxyInitialFetchTimeout          uint
	ProxyGID                          uint
	ProxyMaxRequestsPerConnection     int
	ProxyMaxConnectionDurationSeconds int
	ProxyIdleTimeoutSeconds           int
	ProxyMaxConcurrentRetries         uint32
	HTTPNormalizePath                 bool
	HTTPRequestTimeout                uint
	HTTPIdleTimeout                   uint
	HTTPMaxGRPCTimeout                uint
	HTTPRetryCount                    uint
	HTTPRetryTimeout                  uint
	HTTPStreamIdleTimeout             uint
	UseFullTLSContext                 bool
	ProxyXffNumTrustedHopsIngress     uint32
	ProxyXffNumTrustedHopsEgress      uint32
	EnvoyPolicyRestoreTimeout         time.Duration
	EnvoyHTTPUpstreamLingerTimeout    int
}

func (r ProxyConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("disable-envoy-version-check", false, "Do not perform Envoy version check")
	flags.Int("proxy-prometheus-port", 0, "Port to serve Envoy metrics on. Default 0 (disabled).")
	flags.Int("proxy-admin-port", 0, "Port to serve Envoy admin interface on.")
	flags.Uint("envoy-access-log-buffer-size", 4096, "Envoy access log buffer size in bytes")
	flags.String("envoy-log", "", "Path to a separate Envoy log file, if any")
	flags.String("envoy-default-log-level", "", "Default log level of Envoy application log that is configured if Cilium debug / verbose logging isn't enabled. If not defined, the default log level of the Cilium Agent is used.")
	flags.Uint64("envoy-base-id", 0, "Envoy base ID")
	flags.Bool("envoy-keep-cap-netbindservice", false, "Keep capability NET_BIND_SERVICE for Envoy process")
	flags.Uint("proxy-connect-timeout", 2, "Time after which a TCP connect attempt is considered failed unless completed (in seconds)")
	flags.Uint("proxy-initial-fetch-timeout", 30, "Time after which an xDS stream is considered timed out (in seconds)")
	flags.Uint("proxy-gid", 1337, "Group ID for proxy control plane sockets.")
	flags.Int("proxy-max-requests-per-connection", 0, "Set Envoy HTTP option max_requests_per_connection. Default 0 (disable)")
	flags.Int("proxy-max-connection-duration-seconds", 0, "Set Envoy HTTP option max_connection_duration seconds. Default 0 (disable)")
	flags.Int("proxy-idle-timeout-seconds", 60, "Set Envoy upstream HTTP idle connection timeout seconds. Does not apply to connections with pending requests. Default 60s")
	flags.Uint32("proxy-max-concurrent-retries", 128, "Maximum number of concurrent retries on Envoy clusters")
	flags.Bool("http-normalize-path", true, "Use Envoy HTTP path normalization options, which currently includes RFC 3986 path normalization, Envoy merge slashes option, and unescaping and redirecting for paths that contain escaped slashes. These are necessary to keep path based access control functional, and should not interfere with normal operation. Set this to false only with caution.")
	flags.Uint("http-request-timeout", 60*60, "Time after which a forwarded HTTP request is considered failed unless completed (in seconds); Use 0 for unlimited")
	flags.Uint("http-idle-timeout", 0, "Time after which a non-gRPC HTTP stream is considered failed unless traffic in the stream has been processed (in seconds); defaults to 0 (unlimited)")
	flags.Uint("http-max-grpc-timeout", 0, "Time after which a forwarded gRPC request is considered failed unless completed (in seconds). A \"grpc-timeout\" header may override this with a shorter value; defaults to 0 (unlimited)")
	flags.Uint("http-retry-count", 3, "Number of retries performed after a forwarded request attempt fails")
	flags.Uint("http-retry-timeout", 0, "Time after which a forwarded but uncompleted request is retried (connection failures are retried immediately); defaults to 0 (never)")
	flags.Uint("http-stream-idle-timeout", 5*60, "Set Envoy the amount of time that the connection manager will allow a stream to exist with no upstream or downstream activity. Default 300s")
	// This should default to false in 1.16+ (i.e., we don't implement buggy behaviour) and true in 1.15 and earlier (i.e., we keep compatibility with an existing bug).
	flags.Bool("use-full-tls-context", false, "If enabled, persist ca.crt keys into the Envoy config even in a terminatingTLS block on an L7 Cilium Policy. This is to enable compatibility with previously buggy behaviour. This flag is deprecated and will be removed in a future release.")
	flags.Uint32("proxy-xff-num-trusted-hops-ingress", 0, "Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the ingress L7 policy enforcement Envoy listeners.")
	flags.Uint32("proxy-xff-num-trusted-hops-egress", 0, "Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the egress L7 policy enforcement Envoy listeners.")
	flags.Duration("envoy-policy-restore-timeout", 3*time.Minute, "Maxiumum time to wait for enpoint policy restoration before starting serving resources to Envoy")
	flags.Int("envoy-http-upstream-linger-timeout", -1, "Time in seconds to block Envoy worker thread while an upstream HTTP connection is closing. "+
		"If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background.")
}

type secretSyncConfig struct {
	EnvoySecretsNamespace string

	EnableIngressController bool
	IngressSecretsNamespace string

	EnableGatewayAPI           bool
	GatewayAPISecretsNamespace string
}

func (r secretSyncConfig) Flags(flags *pflag.FlagSet) {
	flags.String("envoy-secrets-namespace", r.EnvoySecretsNamespace, "EnvoySecretsNamespace is the namespace having secrets used by CEC")
	flags.Bool("enable-ingress-controller", false, "Enables Envoy secret sync for Ingress controller related TLS secrets")
	flags.String("ingress-secrets-namespace", r.IngressSecretsNamespace, "IngressSecretsNamespace is the namespace having tls secrets used by CEC, originating from Ingress controller")
	flags.Bool("enable-gateway-api", false, "Enables Envoy secret sync for Gateway API related TLS secrets")
	flags.String("gateway-api-secrets-namespace", r.GatewayAPISecretsNamespace, "GatewayAPISecretsNamespace is the namespace having tls secrets used by CEC, originating from Gateway API")
}

type xdsServerParams struct {
	cell.In

	Lifecycle          cell.Lifecycle
	Logger             *slog.Logger
	IPCache            *ipcache.IPCache
	RestorerPromise    promise.Promise[endpointstate.Restorer]
	LocalEndpointStore *LocalEndpointStore

	EnvoyProxyConfig ProxyConfig

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
			if err := xdsServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy xDS server: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			xdsServer.stop()
			return nil
		},
	})

	if !option.Config.ExternalEnvoyProxy {
		return &onDemandXdsStarter{
			XDSServer:                xdsServer,
			logger:                   params.Logger,
			runDir:                   option.Config.RunDir,
			envoyLogPath:             params.EnvoyProxyConfig.EnvoyLog,
			envoyDefaultLogLevel:     params.EnvoyProxyConfig.EnvoyDefaultLogLevel,
			envoyBaseID:              params.EnvoyProxyConfig.EnvoyBaseID,
			keepCapNetBindService:    params.EnvoyProxyConfig.EnvoyKeepCapNetbindservice,
			metricsListenerPort:      params.EnvoyProxyConfig.ProxyPrometheusPort,
			adminListenerPort:        params.EnvoyProxyConfig.ProxyAdminPort,
			connectTimeout:           int64(params.EnvoyProxyConfig.ProxyConnectTimeout),
			maxRequestsPerConnection: uint32(params.EnvoyProxyConfig.ProxyMaxRequestsPerConnection),
			maxConnectionDuration:    time.Duration(params.EnvoyProxyConfig.ProxyMaxConnectionDurationSeconds) * time.Second,
			idleTimeout:              time.Duration(params.EnvoyProxyConfig.ProxyIdleTimeoutSeconds) * time.Second,
			maxConcurrentRetries:     params.EnvoyProxyConfig.ProxyMaxConcurrentRetries,
		}, nil
	}

	return xdsServer, nil
}

func newEnvoyAdminClient(logger *slog.Logger, envoyProxyConfig ProxyConfig) *EnvoyAdminClient {
	return NewEnvoyAdminClientForSocket(logger, GetSocketDir(option.Config.RunDir), envoyProxyConfig.EnvoyDefaultLogLevel)
}

type accessLogServerParams struct {
	cell.In

	Lifecycle          cell.Lifecycle
	Logger             *slog.Logger
	AccessLogger       accesslog.ProxyAccessLogger
	LocalEndpointStore *LocalEndpointStore
	EnvoyProxyConfig   ProxyConfig
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
			if err := accessLogServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy AccessLog server: %w", err)
			}
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

	Lifecycle        cell.Lifecycle
	Logger           *slog.Logger
	JobRegistry      job.Registry
	Health           cell.Health
	EnvoyProxyConfig ProxyConfig
	EnvoyAdminClient *EnvoyAdminClient
}

func registerEnvoyVersionCheck(params versionCheckParams) {
	if !option.Config.EnableL7Proxy || params.EnvoyProxyConfig.DisableEnvoyVersionCheck {
		return
	}

	checker := &envoyVersionChecker{logger: params.Logger}

	envoyVersionFunc := func() (string, error) {
		return checker.getRemoteEnvoyVersion(params.EnvoyAdminClient)
	}

	if !option.Config.ExternalEnvoyProxy {
		envoyVersionFunc = getEmbeddedEnvoyVersion
	}

	jobGroup := params.JobRegistry.NewGroup(
		params.Health,
		params.Lifecycle,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "envoy")),
	)

	// To prevent agent restarts in case the Envoy DaemonSet isn't ready yet,
	// version check is performed periodically and any errors are logged
	// and reported via health reporter.
	jobGroup.Add(job.Timer("version-check", func(_ context.Context) error {
		if err := checker.checkEnvoyVersion(envoyVersionFunc); err != nil {
			params.Logger.Error("Envoy: Version check failed", logfields.Error, err)
			return err
		}

		return nil
	}, 5*time.Minute))
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

	Logger      *slog.Logger
	Lifecycle   cell.Lifecycle
	JobRegistry job.Registry
	Health      cell.Health

	K8sClientset client.Clientset

	Config        secretSyncConfig
	XdsServer     XDSServer
	SecretManager certificatemanager.SecretManager
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

	jobGroup := params.JobRegistry.NewGroup(
		params.Health,
		params.Lifecycle,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "envoy-secretsyncer")),
	)

	secretSyncerLogger := params.Logger.With(logfields.Controller, "secretSyncer")

	secretSyncer := newSecretSyncer(secretSyncerLogger, params.XdsServer)

	secretSyncerLogger.Debug("Watching namespaces for secrets",
		logfields.K8sNamespace, namespaces,
	)

	for ns := range namespaces {
		jobGroup.Add(job.Observer(
			shortener.ShortenK8sResourceName(fmt.Sprintf("k8s-secrets-resource-events-%s", ns)),
			secretSyncer.handleSecretEvent,
			newK8sSecretResource(params.Lifecycle, params.K8sClientset, ns),
		))
	}

	return nil
}

func newK8sSecretResource(lc cell.Lifecycle, cs client.Clientset, namespace string) resource.Resource[*slim_corev1.Secret] {
	if !cs.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.SecretList](cs.Slim().CoreV1().Secrets(namespace)),
	)

	return resource.New[*slim_corev1.Secret](lc, lw, resource.WithMetric("Secret"))
}
