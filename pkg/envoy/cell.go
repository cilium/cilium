// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime/pprof"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/time"
)

// Cell initializes and manages the Envoy proxy and its control-plane components like xDS- and accesslog server.
// It is used to provide support for Ingress, GatewayAPI and L7 network policies (e.g. HTTP).
var Cell = cell.Module(
	"envoy-proxy",
	"Envoy proxy and control-plane",

	cell.Config(secretSyncConfig{}),
	cell.Provide(newEnvoyXDSServer),
	cell.Provide(newEnvoyAdminClient),
	cell.ProvidePrivate(newEnvoyAccessLogServer),
	cell.ProvidePrivate(newLocalEndpointStore),
	cell.ProvidePrivate(newArtifactCopier),
	cell.Invoke(registerEnvoyVersionCheck),
	cell.Invoke(registerSecretSyncer),
)

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
	IPCache            *ipcache.IPCache
	LocalEndpointStore *LocalEndpointStore

	// Depend on access log server to enforce init order.
	// This ensures that the access log server is ready before it gets used by the
	// Cilium Envoy filter after receiving the resources via xDS server.
	AccessLogServer *AccessLogServer

	// Depend on ArtifactCopier to enforce init order and ensure that the additional artifacts are copied
	// before starting the xDS server (and starting to configure Envoy).
	ArtifactCopier *ArtifactCopier
}

func newEnvoyXDSServer(params xdsServerParams) (XDSServer, error) {
	xdsServer, err := newXDSServer(GetSocketDir(option.Config.RunDir), params.IPCache, params.LocalEndpointStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create Envoy xDS server: %w", err)
	}

	if !option.Config.EnableL7Proxy {
		log.Debug("L7 proxies are disabled - not starting Envoy xDS server")
		return xdsServer, nil
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(startContext cell.HookContext) error {
			if err := xdsServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy xDS server: %w", err)
			}
			return nil
		},
		OnStop: func(stopContext cell.HookContext) error {
			xdsServer.stop()
			return nil
		},
	})

	if !option.Config.ExternalEnvoyProxy {
		return &onDemandXdsStarter{
			XDSServer: xdsServer,
			runDir:    option.Config.RunDir,
		}, nil
	}

	return xdsServer, nil
}

func newEnvoyAdminClient() *EnvoyAdminClient {
	return NewEnvoyAdminClientForSocket(GetSocketDir(option.Config.RunDir))
}

type accessLogServerParams struct {
	cell.In

	Lifecycle          cell.Lifecycle
	LocalEndpointStore *LocalEndpointStore
}

func newEnvoyAccessLogServer(params accessLogServerParams) *AccessLogServer {
	if !option.Config.EnableL7Proxy {
		log.Debug("L7 proxies are disabled - not starting Envoy AccessLog server")
		return nil
	}

	accessLogServer := newAccessLogServer(GetSocketDir(option.Config.RunDir), params.LocalEndpointStore)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(startContext cell.HookContext) error {
			if err := accessLogServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy AccessLog server: %w", err)
			}
			return nil
		},
		OnStop: func(stopContext cell.HookContext) error {
			accessLogServer.stop()
			return nil
		},
	})

	return accessLogServer
}

type versionCheckParams struct {
	cell.In

	Lifecycle        cell.Lifecycle
	Logger           logrus.FieldLogger
	JobRegistry      job.Registry
	Scope            cell.Scope
	EnvoyAdminClient *EnvoyAdminClient
}

func registerEnvoyVersionCheck(params versionCheckParams) {
	if !option.Config.EnableL7Proxy || option.Config.DisableEnvoyVersionCheck {
		return
	}

	envoyVersionFunc := func() (string, error) {
		return getRemoteEnvoyVersion(params.EnvoyAdminClient)
	}

	if !option.Config.ExternalEnvoyProxy {
		envoyVersionFunc = getEmbeddedEnvoyVersion
	}

	jobGroup := params.JobRegistry.NewGroup(
		params.Scope,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "envoy")),
	)
	params.Lifecycle.Append(jobGroup)

	// To prevent agent restarts in case the Envoy DaemonSet isn't ready yet,
	// version check is performed periodically and any errors are logged
	// and reported via health reporter.
	jobGroup.Add(job.Timer("version-check", func(_ context.Context) error {
		if err := checkEnvoyVersion(envoyVersionFunc); err != nil {
			params.Logger.WithError(err).Error("Envoy: Version check failed")
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

func newArtifactCopier(lifecycle cell.Lifecycle) *ArtifactCopier {
	artifactCopier := &ArtifactCopier{
		sourcePath: "/envoy-artifacts",
		targetPath: filepath.Join(option.Config.RunDir, "envoy", "artifacts"),
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(startContext cell.HookContext) error {
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

	Logger      logrus.FieldLogger
	Lifecycle   cell.Lifecycle
	JobRegistry job.Registry
	Scope       cell.Scope

	K8sClientset client.Clientset

	Config    secretSyncConfig
	XdsServer XDSServer
}

func registerSecretSyncer(params syncerParams) error {
	if !params.Config.EnableIngressController && !params.Config.EnableGatewayAPI {
		return nil
	}

	secretSyncer := newSecretSyncer(params.Logger, params.XdsServer)

	// Create a Secret Resource for each namespace.
	// The Cilium Agent only has permissions on the specific namespaces.
	// Note that the different features can use the same namespace for
	// their TLS.
	namespaces := map[string]struct{}{}

	for namespace, cond := range map[string]func() bool{
		params.Config.EnvoySecretsNamespace:      func() bool { return option.Config.EnableEnvoyConfig },
		params.Config.IngressSecretsNamespace:    func() bool { return params.Config.EnableIngressController },
		params.Config.GatewayAPISecretsNamespace: func() bool { return params.Config.EnableGatewayAPI },
	} {
		if len(namespace) > 0 && cond() {
			namespaces[namespace] = struct{}{}
		}
	}

	if len(namespaces) == 0 {
		return nil
	}

	jobGroup := params.JobRegistry.NewGroup(
		params.Scope,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "envoy-secretsyncer")),
	)

	params.Lifecycle.Append(jobGroup)
	for ns := range namespaces {
		jobGroup.Add(job.Observer(
			fmt.Sprintf("k8s-secrets-resource-events-%s", ns),
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
