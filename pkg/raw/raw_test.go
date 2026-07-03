package raw

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/crap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/hive/hivetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

type mockCrapMap struct {
	internal sync.Map
}

func newCrapMapMock() *mockCrapMap {
	return &mockCrapMap{}
}

func (m *mockCrapMap) Delete(key *crap.CrapKey) error {
	m.internal.Delete(key)
	return nil
}

func (m *mockCrapMap) IterateWithCallback(cb crap.CrapIterateCallback) error {
	m.internal.Range(func(key, value any) bool {
		cb(key.(*crap.CrapKey), value.(*crap.CrapVal))

		return true
	})

	return nil
}

func (m *mockCrapMap) Update(key crap.CrapKey, value crap.CrapVal) error {
	m.internal.Store(key, value)
	return nil
}

func (m *mockCrapMap) Lookup(key *crap.CrapKey) (*crap.CrapVal, error) {
	if v, ok := m.internal.Load(key); ok {
		return v.(*crap.CrapVal), nil
	}

	return nil, nil
}

func (m *mockCrapMap) RemoveCrapMapping(dstIP netip.Addr) error {
	return nil
}

func (m *mockCrapMap) UpdateCrapMapping(dstIP netip.Addr, podIp netip.Addr) error {
	return nil
}

type mockEndpointManager struct{}

func (m *mockEndpointManager) LookupIP(id netip.Addr) *endpoint.Endpoint {
	return &endpoint.Endpoint{IPv4: netip.MustParseAddr("1.1.1.1")}
}

type mockIdentityAllocatorSlim struct{}

func (ia *mockIdentityAllocatorSlim) WaitForInitialGlobalIdentities(context.Context) error {
	return nil
}

func (ia *mockIdentityAllocatorSlim) LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity {
	return &identity.Identity{ID: id, Labels: labels.Map2Labels(testSelector, labels.LabelSourceK8s)}
}

var testSelector = map[string]string{
	"app": "test",
}

func newEndpoint(id int64, name, ns, addr string) *types.CiliumEndpoint {
	return &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       k8stypes.UID(uuid.New().String()),
			Labels:    testSelector,
		},
		Identity: &v2.EndpointIdentity{
			ID: id,
		},
		Networking: &v2.EndpointNetworking{
			Addressing: v2.AddressPairList{{
				IPV4: addr,
			}},
			NodeIP: "192.168.1.1",
		},
	}
}

func TestRulesPresence(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	node.SetTestLocalNodeStore()
	bpfMap := newCrapMapMock()

	cm := newCrapManager(CrapParams{
		Logger:            logger,
		BpfMap:            bpfMap,
		EndpointManager:   &mockEndpointManager{},
		IdentityAllocator: &mockIdentityAllocatorSlim{},
	})

	ctx := t.Context()

	go func() {
		err := cm.reconcile(ctx, nil)
		require.NoError(t, err)
	}()

	go func() {
		err := cm.handleSvcEvent(ctx, resource.Event[*slimcorev1.Service]{
			Kind: resource.Upsert,
			Key:  resource.NewKey("svc1"),
			Object: &slimcorev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      "svc1",
					Namespace: "ns1",
					UID:       k8stypes.UID(uuid.New().String()),
					Labels: map[string]string{
						"advertise": "bgp",
					},
					Annotations: map[string]string{
						annotation.ServiceRaw: "true",
					},
				},
				Spec: slimcorev1.ServiceSpec{
					Type:        slimcorev1.ServiceTypeClusterIP,
					ExternalIPs: []string{"1.1.1.1"},
					Ports: []slimcorev1.ServicePort{{
						Name:       "raw",
						Protocol:   slimcorev1.ProtocolTCP,
						Port:       1,
						TargetPort: intstr.FromInt(1),
					}},
					Selector: testSelector,
				},
			},
			Done: func(err error) {},
		})
		require.NoError(t, err)

		err = cm.handleSvcEvent(ctx, resource.Event[*slimcorev1.Service]{
			Kind: resource.Sync,
			Done: func(err error) {},
		})
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		err = cm.handleEndpointEvent(ctx, resource.Event[*types.CiliumEndpoint]{
			Kind:   resource.Upsert,
			Key:    resource.NewKey("pod1"),
			Object: newEndpoint(1, "pod1", "ns1", "2.2.2.2"),
			Done:   func(err error) {},
		})
		require.NoError(t, err)

		err = cm.handleEndpointEvent(ctx, resource.Event[*types.CiliumEndpoint]{
			Kind:   resource.Upsert,
			Key:    resource.NewKey("pod2"),
			Object: newEndpoint(2, "pod2", "ns2", "3.3.3.3"),
			Done:   func(err error) {},
		})
		require.NoError(t, err)

		err = cm.handleEndpointEvent(ctx, resource.Event[*types.CiliumEndpoint]{
			Kind: resource.Sync,
			Done: func(err error) {},
		})
		require.NoError(t, err)
	}()

	cm.svcProcessed = make(chan int)
	cm.epProcessed = make(chan int)

	var svc atomic.Int32
	var ep atomic.Int32

	go func() {
		for c := range cm.svcProcessed {
			svc.Add(int32(c))
		}
	}()
	go func() {
		for c := range cm.epProcessed {
			ep.Add(int32(c))
		}
	}()

	for {
		i := 0

		bpfMap.internal.Range(func(key, value any) bool {
			i++
			return true
		})

		if i == 1 && svc.Load() == 1 && ep.Load() == 2 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}
}
