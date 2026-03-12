// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/defaults"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/version"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type fakePlugin struct {
	instrumentCollectionCount int
	ciliumVersion             string
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

func (p *fakePlugin) InstrumentCollection(ctx context.Context, _ *datapathplugins.InstrumentCollectionRequest) (*datapathplugins.InstrumentCollectionResponse, error) {
	p.instrumentCollectionCount++
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		p.ciliumVersion = md.Get(ciliumVersionMeta)[0]
	}

	return nil, nil
}

func TestRegistry(t *testing.T) {
	logger := hivetest.Logger(t)
	tmp := t.TempDir()
	pluginA := startFakePlugin(t, tmp, "plugin_a")
	pluginB := startFakePlugin(t, tmp, "plugin_b")
	registry := newRegistry(logger, nil, datapathPluginsConfig{
		DatapathPluginsStateDir: tmp,
	})
	registry.Register(&api_v2alpha1.CiliumDatapathPlugin{
		ObjectMeta: metav1.ObjectMeta{
			Name: "plugin_a",
		},
		Spec: api_v2alpha1.CiliumDatapathPluginSpec{
			AttachmentPolicy: api_v2alpha1.AttachmentPolicyAlways,
		},
	})
	registry.Register(&api_v2alpha1.CiliumDatapathPlugin{
		ObjectMeta: metav1.ObjectMeta{
			Name: "plugin_b",
		},
		Spec: api_v2alpha1.CiliumDatapathPluginSpec{
			AttachmentPolicy: api_v2alpha1.AttachmentPolicyAlways,
		},
	})
	registry.Register(&api_v2alpha1.CiliumDatapathPlugin{
		ObjectMeta: metav1.ObjectMeta{
			Name: "plugin_c",
		},
		Spec: api_v2alpha1.CiliumDatapathPluginSpec{
			AttachmentPolicy: api_v2alpha1.AttachmentPolicyAlways,
		},
	})

	plugins := registry.Plugins()
	assert.Contains(t, plugins, "plugin_a")
	assert.Contains(t, plugins, "plugin_b")
	assert.Contains(t, plugins, "plugin_c")
	assert.Equal(t, 0, pluginA.instrumentCollectionCount)
	assert.Equal(t, 0, pluginB.instrumentCollectionCount)

	_, err := plugins["plugin_a"].InstrumentCollection(t.Context(), &datapathplugins.InstrumentCollectionRequest{})
	assert.NoError(t, err)
	_, err = plugins["plugin_b"].InstrumentCollection(t.Context(), &datapathplugins.InstrumentCollectionRequest{})
	assert.NoError(t, err)
	_, err = plugins["plugin_c"].InstrumentCollection(t.Context(), &datapathplugins.InstrumentCollectionRequest{})
	assert.Error(t, err)
	assert.Equal(t, 1, pluginA.instrumentCollectionCount)
	assert.Equal(t, 1, pluginB.instrumentCollectionCount)
	assert.Equal(t, version.Version, pluginA.ciliumVersion)
	assert.Equal(t, version.Version, pluginB.ciliumVersion)

	registry.Unregister(&api_v2alpha1.CiliumDatapathPlugin{
		ObjectMeta: metav1.ObjectMeta{
			Name: "plugin_b",
		},
		Spec: api_v2alpha1.CiliumDatapathPluginSpec{
			AttachmentPolicy: api_v2alpha1.AttachmentPolicyAlways,
		},
	})

	plugins = registry.Plugins()
	assert.Contains(t, plugins, "plugin_a")
	assert.NotContains(t, plugins, "plugin_b")
	assert.Contains(t, plugins, "plugin_c")
}
