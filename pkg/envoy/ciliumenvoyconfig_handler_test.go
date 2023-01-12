package envoy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/status"
)

type mockEnvoyCache struct{}

// AckProxyPort implements EnvoyCache
func (*mockEnvoyCache) AckProxyPort(ctx context.Context, name string) error {
	panic("unimplemented")
}

// AllocateProxyPort implements EnvoyCache
func (*mockEnvoyCache) AllocateProxyPort(name string, ingress bool) (uint16, error) {
	panic("unimplemented")
}

// ReleaseProxyPort implements EnvoyCache
func (*mockEnvoyCache) ReleaseProxyPort(name string) error {
	panic("unimplemented")
}

// UpsertEnvoyEndpoints implements EnvoyCache
func (*mockEnvoyCache) UpsertEnvoyEndpoints(loadbalancer.ServiceName, map[string][]*loadbalancer.Backend) error {
	panic("unimplemented")
}

// UpsertEnvoyResources implements EnvoyCache
func (*mockEnvoyCache) UpsertEnvoyResources(context.Context, Resources) error {
	panic("unimplemented")
}

var _ EnvoyCache = &mockEnvoyCache{}

type mockServiceManager struct {
	events chan servicemanager.Event
	calls  chan string
}

// Close implements servicemanager.ServiceHandle
func (sm *mockServiceManager) Close() {
	sm.calls <- "Close"
	close(sm.calls)
}

// DeleteBackends implements servicemanager.ServiceHandle
func (*mockServiceManager) DeleteBackends(name loadbalancer.ServiceName, addrs ...loadbalancer.L3n4Addr) {
	panic("unimplemented")
}

// DeleteFrontend implements servicemanager.ServiceHandle
func (*mockServiceManager) DeleteFrontend(fe loadbalancer.FE) {
	panic("unimplemented")
}

func (m *mockServiceManager) Events() <-chan servicemanager.Event {
	return m.events
}
func (m *mockServiceManager) Observe(name loadbalancer.ServiceName) {
	m.calls <- "Observe:" + name.String()
}
func (*mockServiceManager) RemoveLocalRedirects(name loadbalancer.ServiceName) {
	panic("unimplemented")
}
func (m *mockServiceManager) RemoveProxyRedirect(name loadbalancer.ServiceName) {
	m.calls <- fmt.Sprintf("RemoveProxyRedirect:%s", name)
}
func (m *mockServiceManager) SetLocalRedirects(name loadbalancer.ServiceName, config servicemanager.LocalRedirectConfig) {
	panic("unimplemented")
}
func (m *mockServiceManager) SetProxyRedirect(name loadbalancer.ServiceName, proxyPort uint16) {
	m.calls <- fmt.Sprintf("SetProxyRedirect:%s:%d", name, proxyPort)
}
func (m *mockServiceManager) Synchronized() {
	m.calls <- "Synchronized"
}
func (m *mockServiceManager) Unobserve(name loadbalancer.ServiceName) {
	m.calls <- "Unobserve:" + name.String()
}
func (*mockServiceManager) UpsertBackends(name loadbalancer.ServiceName, backends ...loadbalancer.Backend) {
	panic("unimplemented")
}
func (*mockServiceManager) UpsertFrontend(fe loadbalancer.FE) {
	panic("unimplemented")
}

// NewHandle implements servicemanager.ServiceManager
func (m *mockServiceManager) NewHandle(name string) servicemanager.ServiceHandle {
	return m
}

var _ servicemanager.ServiceManager = &mockServiceManager{}
var _ servicemanager.ServiceHandle = &mockServiceManager{}

func TestEnvoyConfigHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		fcs        *client.FakeClientset
		envoyCache = &mockEnvoyCache{}
		sm         = &mockServiceManager{
			events: make(chan servicemanager.Event, 10),
			calls:  make(chan string, 16),
		}
		statusUpdates <-chan status.ModuleStatus
	)

	h := hive.New(
		client.FakeClientCell,
		EnvoyConfigHandlerCell,
		k8s.SharedResourcesCell,
		cell.Provide(func() (EnvoyCache, servicemanager.ServiceManager) {
			return envoyCache, sm
		}),
		cell.Invoke(func(cs *client.FakeClientset, sp *status.Provider) {
			fcs = cs
			statusUpdates = sp.Stream(ctx)
		}),
	)

	err := h.Start(context.TODO())
	assert.NoError(t, err, "Start")

	s := <-statusUpdates
	assert.Equal(t, status.LevelOK, s.Level)

	var cec cilium_v2.CiliumEnvoyConfig
	err = yaml.Unmarshal([]byte(ciliumEnvoyConfig), &cec)
	assert.NoError(t, err)
	cec.Spec.Services = []*cilium_v2.ServiceListener{
		{
			Name:      "svc1",
			Namespace: "svcs",
			Listener:  "foo/envoy-prometheus-metrics-listener/envoy-prometheus-metrics-listener",
		},
		{
			Name:      "svc2",
			Namespace: "svcs",
			Listener:  "foo/envoy-prometheus-metrics-listener/envoy-prometheus-metrics-listener",
		},
	}

	// Test creation happy path
	cecs := fcs.CiliumV2().CiliumEnvoyConfigs("foo")
	_, err = cecs.Create(ctx, &cec, v1.CreateOptions{})
	assert.NoError(t, err, "cecs.Create")

	assert.Equal(t, "SetProxyRedirect:svc/svcs/svc1:10000", <-sm.calls)
	assert.Equal(t, "Observe:svc/svcs/svc1", <-sm.calls)
	assert.Equal(t, "SetProxyRedirect:svc/svcs/svc2:10000", <-sm.calls)
	assert.Equal(t, "Observe:svc/svcs/svc2", <-sm.calls)

	s = <-statusUpdates
	assert.Equal(t, status.LevelOK, s.Level)

	assert.Equal(t, "Synchronized", <-sm.calls)

	// Test update that deletes a service reference
	cec.Spec.Services = cec.Spec.Services[1:]
	_, err = cecs.Update(ctx, &cec, v1.UpdateOptions{})
	assert.NoError(t, err, "cecs.Update")

	assert.Equal(t, "RemoveProxyRedirect:svc/svcs/svc1", <-sm.calls)
	assert.Equal(t, "Unobserve:svc/svcs/svc1", <-sm.calls)
	s = <-statusUpdates
	assert.Equal(t, status.LevelOK, s.Level)

	// Test update with faulty service reference
	cec.Spec.Services = append(cec.Spec.Services,
		&cilium_v2.ServiceListener{
			Name:      "svc3",
			Namespace: "svcs",
			Listener:  "non-existing",
		})

	_, err = cecs.Update(ctx, &cec, v1.UpdateOptions{})
	assert.NoError(t, err, "cecs.Update")

	s = <-statusUpdates
	assert.Equal(t, status.LevelDegraded, s.Level)
	assert.Contains(t, s.Message, "Listener \"non-existing\" not found")

	// TODO test overlap
	// TODO test parse error

	// Test deletion
	err = cecs.Delete(ctx, cec.Name, v1.DeleteOptions{})
	assert.NoError(t, err, "cecs.Delete")

	assert.Equal(t, "RemoveProxyRedirect:svc/svcs/svc2", <-sm.calls)
	assert.Equal(t, "Unobserve:svc/svcs/svc2", <-sm.calls)

	err = h.Stop(context.TODO())
	assert.NoError(t, err, "Stop")

	assert.Equal(t, "Close", <-sm.calls)
}
