package plugins

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/datapath/plugins/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	sockFileName = "plugin.sock"
)

func pluginStateDir(stateDir, name string) string {
	return filepath.Join(stateDir, name)
}

func pluginSocketFile(stateDir, name string) string {
	return filepath.Join(pluginStateDir(stateDir, name), sockFileName)
}

type registry struct {
	mu                     sync.Mutex
	enabled                bool
	logger                 *slog.Logger
	registry               map[string]*plugin
	datapathPluginStateDir string
}

func newRegistry(logger *slog.Logger, config datapathPluginsConfig) types.Registry {
	if !config.DatapathPluginsEnabled {
		logger.Info("Disabling datapath plugins.")
	} else {
		logger.Info("Enabling datapath plugins", logfields.Path, config.DatapathPluginsStateDir)
	}

	return &registry{
		enabled:                config.DatapathPluginsEnabled,
		logger:                 logger,
		registry:               make(map[string]*plugin),
		datapathPluginStateDir: config.DatapathPluginsStateDir,
	}
}

func (m *registry) IsEnabled() bool {
	return m.enabled
}

func (m *registry) Register(datapathPlugin *api_v2alpha1.CiliumDatapathPlugin) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.registry[datapathPlugin.Name]
	if ok {
		p.dpp = datapathPlugin
	}

	p = &plugin{dpp: datapathPlugin}
	c, err := grpc.NewClient("unix://"+pluginSocketFile(m.datapathPluginStateDir, datapathPlugin.Name), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		m.logger.Error("Could not create client for plugin",
			logfields.Error, err,
			"plugin", datapathPlugin.Name,
		)
		p.DatapathPluginClient = &errorClient{err: err}
	} else {
		p.DatapathPluginClient = datapathplugins.NewDatapathPluginClient(c)
		p.conn = c
	}

	m.registry[datapathPlugin.Name] = p
}

func (m *registry) Unregister(datapathPlugin *api_v2alpha1.CiliumDatapathPlugin) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.registry[datapathPlugin.Name]
	if ok {
		delete(m.registry, datapathPlugin.Name)
		p.close()
	}

}

func (m *registry) Plugins() types.Plugins {
	m.mu.Lock()
	defer m.mu.Unlock()

	snapshot := make(map[string]types.Plugin)

	for name, plugin := range m.registry {
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
