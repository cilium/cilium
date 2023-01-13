package envoy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/controlplane/servicemanager"
	pkgEnvoy "github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
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
func (*mockEnvoyCache) UpsertEnvoyResources(context.Context, pkgEnvoy.Resources) error {
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
func (*mockServiceManager) UpsertBackends(name loadbalancer.ServiceName, backends ...*loadbalancer.Backend) {
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
	)

	h := hive.New(
		client.FakeClientCell,
		EnvoyConfigHandlerCell,
		k8s.SharedResourcesCell,
		cell.Provide(func() (EnvoyCache, servicemanager.ServiceManager) {
			return envoyCache, sm
		}),
		cell.Invoke(func(cs *client.FakeClientset) {
			fcs = cs
		}),
	)

	err := h.Start(context.TODO())
	assert.NoError(t, err, "Start")

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

	assert.Equal(t, "Synchronized", <-sm.calls)

	// Test update that deletes a service reference
	cec.Spec.Services = cec.Spec.Services[1:]
	_, err = cecs.Update(ctx, &cec, v1.UpdateOptions{})
	assert.NoError(t, err, "cecs.Update")

	assert.Equal(t, "RemoveProxyRedirect:svc/svcs/svc1", <-sm.calls)
	assert.Equal(t, "Unobserve:svc/svcs/svc1", <-sm.calls)

	// Test update with faulty service reference
	cec.Spec.Services = append(cec.Spec.Services,
		&cilium_v2.ServiceListener{
			Name:      "svc3",
			Namespace: "svcs",
			Listener:  "non-existing",
		})

	_, err = cecs.Update(ctx, &cec, v1.UpdateOptions{})
	assert.NoError(t, err, "cecs.Update")

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

var ciliumEnvoyConfig = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: envoy-prometheus-metrics-listener
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          codec_type: AUTO
          rds:
            route_config_name: local_route
          http_filters:
          - name: envoy.filters.http.router
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificate_sds_secret_configs:
            - name: cilium-secrets/server-mtls
            validation_context_sds_secret_config:
              name: cilium-secrets/server-mtls
`
