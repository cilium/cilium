// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/datapath/plugins/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	sockFileName      = "plugin.sock"
	ciliumVersionMeta = "cilium_version"
)

func pluginStateDir(stateDir, name string) string {
	return filepath.Join(stateDir, name)
}

func pluginSocketFile(stateDir, name string) string {
	return filepath.Join(pluginStateDir(stateDir, name), sockFileName)
}

type syncChan chan struct{}

func newSyncChan() syncChan {
	return make(chan struct{})
}

type registry struct {
	mu                     lock.Mutex
	logger                 *slog.Logger
	registry               map[string]*plugin
	datapathPluginStateDir string
	synced                 syncChan
}

func newRegistry(logger *slog.Logger, synced syncChan, config datapathPluginsConfig) types.Registry {
	if !option.Config.EnableDatapathPlugins {
		logger.Info("Datapath plugins are disabled.")
	} else {
		logger.Info("Datapath plugins are enabled", logfields.Path, config.DatapathPluginsStateDir)
	}

	return &registry{
		logger:                 logger,
		registry:               make(map[string]*plugin),
		datapathPluginStateDir: config.DatapathPluginsStateDir,
		synced:                 synced,
	}
}

// Sync blocks until the registry is initialized or until ctx is done.
func (m *registry) Sync(ctx context.Context) error {
	if !option.Config.EnableDatapathPlugins {
		return nil
	}

	select {
	case <-m.synced:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Register registers a plugin and sets up a client to talk to it.
func (r *registry) Register(datapathPlugin *api_v2alpha1.CiliumDatapathPlugin) {
	r.mu.Lock()
	defer r.mu.Unlock()

	logger := r.logger.With(
		logfields.CiliumDatapathPluginName, datapathPlugin.Name,
		logfields.CiliumDatapathPluginAttachmentPolicy, datapathPlugin.Spec.AttachmentPolicy,
		logfields.CiliumDatapathPluginVersion, datapathPlugin.Spec.Version,
	)

	p, ok := r.registry[datapathPlugin.Name]
	if ok {
		logger.Info("Update datapath plugin")
		p.dpp = datapathPlugin
		return
	}

	p = &plugin{dpp: datapathPlugin}
	sockPath := "unix://" + pluginSocketFile(r.datapathPluginStateDir, datapathPlugin.Name)
	c, err := grpc.NewClient(
		sockPath,
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(
				metadata.AppendToOutgoingContext(ctx, ciliumVersionMeta, version.Version),
				method,
				req,
				reply,
				cc,
				opts...,
			)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		logger.Error("Could not create client for plugin", logfields.Error, err)

		// Something weird happened; grpc.NewClient() should succeed even if the plugin
		// isn't up or the unix socket path doesn't exist, as it doesn't actually set
		// up any connections yet. Still, we need to make sure this plugin is reflected
		// in the registry, and that datapath (re)initialization doesn't proceed and
		// succeed without consulting this plugin. In particular, the attachment policy
		// may currently be or later be set to "Always", in which case it would be
		// incorrect to allow datapath programming to proceed without this plugin.
		// If the attachment policy is "BestEffort", the loader won't care if requests
		// fail anyway.
		p.DatapathPluginClient = &errorClient{err: err}
	} else {
		p.DatapathPluginClient = datapathplugins.NewDatapathPluginClient(c)
		p.conn = c
	}

	logger.Info("Register plugin", logfields.Path, sockPath)

	r.registry[datapathPlugin.Name] = p
}

// Unregister unregisters a plugin and shuts down its client.
func (r *registry) Unregister(datapathPlugin *api_v2alpha1.CiliumDatapathPlugin) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.registry[datapathPlugin.Name]
	if ok {
		delete(r.registry, datapathPlugin.Name)
		p.close()
	}

	r.logger.Info("Unregister plugin")
}

// Plugins returns a snapshot of the current state of the registry.
func (r *registry) Plugins() types.Plugins {
	r.mu.Lock()
	defer r.mu.Unlock()

	snapshot := make(map[string]types.Plugin)

	for name, plugin := range r.registry {
		cp := *plugin
		snapshot[name] = &cp
	}

	return snapshot
}

type plugin struct {
	datapathplugins.DatapathPluginClient
	dpp  *api_v2alpha1.CiliumDatapathPlugin
	conn *grpc.ClientConn
}

func (p *plugin) Name() string {
	return p.dpp.Name
}

func (p *plugin) AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy {
	return p.dpp.Spec.AttachmentPolicy
}

func (p *plugin) DeepEqual(o types.Plugin) bool {
	other, ok := o.(*plugin)
	if !ok {
		return false
	}

	return p.dpp.DeepEqual(other.dpp)
}

func (p *plugin) close() error {
	if p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

type errorClient struct {
	err error
}

func (c *errorClient) PrepareCollection(ctx context.Context, in *datapathplugins.PrepareCollectionRequest, opts ...grpc.CallOption) (*datapathplugins.PrepareCollectionResponse, error) {
	return nil, fmt.Errorf("gRPC client could not be initialized: %w", c.err)
}

func (c *errorClient) InstrumentCollection(ctx context.Context, in *datapathplugins.InstrumentCollectionRequest, opts ...grpc.CallOption) (*datapathplugins.InstrumentCollectionResponse, error) {
	return nil, fmt.Errorf("gRPC client could not be initialized: %w", c.err)
}
