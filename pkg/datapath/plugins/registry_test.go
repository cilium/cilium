package plugins

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/datapath/plugins/types"
	"github.com/cilium/cilium/pkg/defaults"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
)

type fakePlugin struct {
	instrumentCollectionCount int
}

func startFakePlugin(t *testing.T, stateDir, name string) *fakePlugin {
	t.Helper()

	require.NoError(t, os.MkdirAll(pluginStateDir(stateDir, name), defaults.StateDirRights))
	addr, err := net.ResolveUnixAddr("unix", pluginSocketFile(stateDir, name))
	require.NoError(t, err)
	listener, err := net.ListenUnix("unix", addr)
	require.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})

	server := grpc.NewServer()
	plugin := &fakePlugin{}
	datapathplugins.RegisterDatapathPluginServer(server, plugin)

	go server.Serve(listener)

	return plugin
}

func (p *fakePlugin) PrepareCollection(_ context.Context, _ *datapathplugins.PrepareCollectionRequest) (*datapathplugins.PrepareCollectionResponse, error) {
	return nil, nil
}

func (p *fakePlugin) InstrumentCollection(_ context.Context, _ *datapathplugins.InstrumentCollectionRequest) (*datapathplugins.InstrumentCollectionResponse, error) {
	p.instrumentCollectionCount++

	return nil, nil
}

func TestRegistry(t *testing.T) {
	logger := hivetest.Logger(t)
	tmp := t.TempDir()
	pluginA := startFakePlugin(t, tmp, "plugin_a")
	pluginB := startFakePlugin(t, tmp, "plugin_b")
	registry := newRegistry(logger, datapathPluginsConfig{
		DatapathPluginsEnabled:  true,
		DatapathPluginsStateDir: tmp,
	})

	require.NoError(t, registry.Register(types.DatapathPlugin{
		Name:             "plugin_a",
		AttachmentPolicy: api_v2alpha1.AttachmentPolicyAlways,
	}))
	require.NoError(t, registry.Register(types.DatapathPlugin{
		Name:             "plugin_b",
		AttachmentPolicy: api_v2alpha1.AttachmentPolicyAlways,
	}))

	plugins := registry.Plugins()
	assert.Contains(t, plugins, "plugin_a")
	assert.Contains(t, plugins, "plugin_b")
	assert.Equal(t, pluginA.instrumentCollectionCount, 0)
	assert.Equal(t, pluginB.instrumentCollectionCount, 0)

	_, err := plugins["plugin_a"].InstrumentCollection(t.Context(), &datapathplugins.InstrumentCollectionRequest{})
	assert.NoError(t, err)
	_, err = plugins["plugin_b"].InstrumentCollection(t.Context(), &datapathplugins.InstrumentCollectionRequest{})
	assert.NoError(t, err)
	assert.Equal(t, pluginA.instrumentCollectionCount, 1)
	assert.Equal(t, pluginB.instrumentCollectionCount, 1)

	require.NoError(t, registry.Unregister(types.DatapathPlugin{
		Name:             "plugin_b",
		AttachmentPolicy: api_v2alpha1.AttachmentPolicyAlways,
	}))

	plugins = registry.Plugins()
	assert.Contains(t, plugins, "plugin_a")
	assert.NotContains(t, plugins, "plugin_b")
}
