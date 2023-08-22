// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
)

// Cell initializes and manages the Envoy proxy and its control-plane components like xDS- and accesslog server.
// It is used to provide support for Ingress, GatewayAPI and L7 network policies (e.g. HTTP).
var Cell = cell.Module(
	"envoy-proxy",
	"Envoy proxy and control-plane",

	cell.Provide(newEnvoyXDSServer),
	cell.Provide(newEnvoyAdminClient),
	cell.ProvidePrivate(newEnvoyAccessLogServer),
	cell.ProvidePrivate(newLocalEndpointStore),
	cell.ProvidePrivate(newArtifactCopier),
	cell.Invoke(registerEnvoyVersionCheck),
)

type xdsServerParams struct {
	cell.In

	Lifecycle          hive.Lifecycle
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

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(startContext hive.HookContext) error {
			if err := xdsServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy xDS server: %w", err)
			}
			return nil
		},
		OnStop: func(stopContext hive.HookContext) error {
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

	Lifecycle          hive.Lifecycle
	LocalEndpointStore *LocalEndpointStore
}

func newEnvoyAccessLogServer(params accessLogServerParams) *AccessLogServer {
	if !option.Config.EnableL7Proxy {
		log.Debug("L7 proxies are disabled - not starting Envoy AccessLog server")
		return nil
	}

	accessLogServer := newAccessLogServer(GetSocketDir(option.Config.RunDir), params.LocalEndpointStore)

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(startContext hive.HookContext) error {
			if err := accessLogServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy AccessLog server: %w", err)
			}
			return nil
		},
		OnStop: func(stopContext hive.HookContext) error {
			accessLogServer.stop()
			return nil
		},
	})

	return accessLogServer
}

type versionCheckParams struct {
	cell.In

	Lifecycle        hive.Lifecycle
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

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(startContext hive.HookContext) error {
			// To prevent agent restarts in case the Envoy DaemonSet isn't ready yet,
			// version check is performed asynchronously and errors are only logged.
			go func() {
				if err := checkEnvoyVersion(envoyVersionFunc); err != nil {
					log.WithError(err).Error("Envoy: Version check failed")
				}
			}()

			return nil
		},
	})
}

func newLocalEndpointStore() *LocalEndpointStore {
	return &LocalEndpointStore{
		networkPolicyEndpoints: make(map[string]endpoint.EndpointUpdater),
	}
}

func newArtifactCopier(lifecycle hive.Lifecycle) *ArtifactCopier {
	artifactCopier := &ArtifactCopier{
		sourcePath: "/envoy-artifacts",
		targetPath: filepath.Join(option.Config.RunDir, "envoy", "artifacts"),
	}

	lifecycle.Append(hive.Hook{
		OnStart: func(startContext hive.HookContext) error {
			if err := artifactCopier.Copy(); err != nil {
				return fmt.Errorf("failed to copy artifacts to envoy: %w", err)
			}
			return nil
		},
	})

	return artifactCopier
}
