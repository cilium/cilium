// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity/cache"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/types"
)

type EndpointSuite struct {
	regeneration.Owner
	repo     *policy.Repository
	datapath datapath.Datapath
	mgr      *cache.CachingIdentityAllocator

	// Owners interface mock
	OnGetPolicyRepository     func() *policy.Repository
	OnGetNamedPorts           func() (npm types.NamedPortMultiMap)
	OnQueueEndpointBuild      func(ctx context.Context, epID uint64) (func(), error)
	OnRemoveFromEndpointQueue func(epID uint64)
	OnGetCompilationLock      func() datapath.CompilationLock
	OnSendNotification        func(msg monitorAPI.AgentNotifyMessage) error
}

func setupEndpointSuite(tb testing.TB) *EndpointSuite {
	testutils.IntegrationTest(tb)

	s := &EndpointSuite{}
	s.repo = policy.NewPolicyRepository(nil, nil, nil, nil)
	// GetConfig the default labels prefix filter
	err := labelsfilter.ParseLabelPrefixCfg(nil, nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}

	// Register metrics once before running the suite
	metrics.NewLegacyMetrics().EndpointStateCount.SetEnabled(true)

	/* Required to test endpoint CEP policy model */
	kvstore.SetupDummy(tb, "etcd")
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	<-mgr.InitIdentityAllocator(nil)
	s.mgr = mgr
	node.SetTestLocalNodeStore()

	tb.Cleanup(func() {
		metrics.NewLegacyMetrics().EndpointStateCount.SetEnabled(false)

		s.mgr.Close()
		node.UnsetTestLocalNodeStore()
	})

	return s
}

func (s *EndpointSuite) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s *EndpointSuite) GetNamedPorts() (npm types.NamedPortMultiMap) {
	if s.OnGetNamedPorts != nil {
		return s.OnGetNamedPorts()
	}
	panic("GetNamedPorts should not have been called")
}

func (s *EndpointSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *EndpointSuite) GetCompilationLock() datapath.CompilationLock {
	return nil
}

func (s *EndpointSuite) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

func (s *EndpointSuite) Datapath() datapath.Datapath {
	return s.datapath
}

func (s *EndpointSuite) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *EndpointSuite) RemoveRestoredDNSRules(epID uint16) {
}

func TestEndpointStatus(t *testing.T) {
	setupEndpointSuite(t)

	eps := NewEndpointStatus()

	require.Equal(t, "OK", eps.String())

	sts := &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "BPF Program compiled",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	require.Equal(t, "OK", eps.String())

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "BPF Program failed to compile",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	require.Equal(t, "Failure", eps.String())

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	require.Equal(t, "Failure", eps.String())

	// An OK message with priority Other can't hide a High Failure message.
	for i := 0; i <= maxLogs; i++ {
		st := &statusLogMsg{
			Status: Status{
				Code: OK,
				Msg:  "Other thing compiled",
				Type: Other,
			},
			Timestamp: time.Now(),
		}
		eps.addStatusLog(st)
	}
	eps.addStatusLog(sts)
	require.Equal(t, "Failure", eps.String())

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	require.Equal(t, "Failure", eps.String())

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "BPF Program compiled",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	// BPF might be ok but the policy is still in fail mode.
	require.Equal(t, "Failure", eps.String())

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	require.Equal(t, "Failure", eps.String())

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	require.Equal(t, "OK", eps.String())
}

func TestEndpointDatapathOptions(t *testing.T) {
	s := setupEndpointSuite(t)

	e, err := NewEndpointFromChangeModel(context.TODO(), s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, s.mgr, &models.EndpointChangeRequest{
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			DisableSipVerification: true,
		},
	})
	require.Nil(t, err)
	require.Equal(t, option.OptionDisabled, e.Options.GetValue(option.SourceIPVerification))
}

func TestEndpointUpdateLabels(t *testing.T) {
	s := setupEndpointSuite(t)

	e := NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 100, StateWaitingForIdentity)

	// Test that inserting identity labels works
	rev := e.replaceIdentityLabels(labels.LabelSourceAny, labels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	require.NotEqual(t, 0, rev)
	require.Equal(t, "cilium:foo=bar;cilium:zip=zop;", string(e.OpLabels.OrchestrationIdentity.SortedList()))
	// Test that nothing changes
	rev = e.replaceIdentityLabels(labels.LabelSourceAny, labels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	require.Equal(t, 0, rev)
	require.Equal(t, "cilium:foo=bar;cilium:zip=zop;", string(e.OpLabels.OrchestrationIdentity.SortedList()))
	// Remove one label, change the source and value of the other.
	rev = e.replaceIdentityLabels(labels.LabelSourceAny, labels.Map2Labels(map[string]string{"foo": "zop"}, "cilium"))
	require.NotEqual(t, 0, rev)
	require.Equal(t, "cilium:foo=zop;", string(e.OpLabels.OrchestrationIdentity.SortedList()))

	// Test that inserting information labels works
	e.replaceInformationLabels(labels.LabelSourceAny, labels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	require.Equal(t, "cilium:foo=bar;cilium:zip=zop;", string(e.OpLabels.OrchestrationInfo.SortedList()))

	// Test that inserting a new nginx will also keep the previous cilium label
	e.replaceInformationLabels("nginx", labels.Map2Labels(map[string]string{"foo2": "zop2", "zip": "zop2"}, "nginx"))
	require.Equal(t, "cilium:foo=bar;nginx:foo2=zop2;cilium:zip=zop;", string(e.OpLabels.OrchestrationInfo.SortedList()))

	// Test that we will keep the 'nginx' label because we only want to add
	// Cilium labels.
	e.replaceInformationLabels("cilium", labels.Map2Labels(map[string]string{"foo2": "bar2", "zip2": "zop2"}, "cilium"))
	require.Equal(t, "nginx:foo2=zop2;cilium:zip2=zop2;", string(e.OpLabels.OrchestrationInfo.SortedList()))

	// Test that we will keep the 'nginx' label because we only want to update
	// Cilium labels.
	e.replaceInformationLabels("cilium", labels.Map2Labels(map[string]string{"foo3": "bar3"}, "cilium"))
	require.Equal(t, "nginx:foo2=zop2;cilium:foo3=bar3;", string(e.OpLabels.OrchestrationInfo.SortedList()))

	// Test that we will not replace labels from other sources if the key is the same.
	e.replaceInformationLabels(labels.LabelSourceAny, labels.Map2Labels(map[string]string{"foo2": "bar2"}, "cilium"))
	require.Equal(t, "nginx:foo2=zop2;", string(e.OpLabels.OrchestrationInfo.SortedList()))
}

func TestEndpointState(t *testing.T) {
	s := setupEndpointSuite(t)

	e := NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 100, StateWaitingForIdentity)
	e.unconditionalLock()
	defer e.unlock()

	assertStateTransition(t, e, e.setState, StateWaitingForIdentity, StateWaitingForIdentity, false)

	assertStateTransition(t, e, e.setState, StateWaitingForIdentity, StateReady, true)

	assertStateTransition(t, e, e.setState, StateWaitingForIdentity, StateWaitingToRegenerate, false)
	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(t, e, e.setState, StateRegenerating, StateDisconnecting, true)

	assertStateTransition(t, e, e.setState, StateWaitingForIdentity, StateDisconnected, false)

	assertStateTransition(t, e, e.setState, StateReady, StateWaitingForIdentity, true)
	assertStateTransition(t, e, e.setState, StateReady, StateReady, false)
	assertStateTransition(t, e, e.setState, StateReady, StateWaitingToRegenerate, true)
	assertStateTransition(t, e, e.setState, StateReady, StateRegenerating, false)
	assertStateTransition(t, e, e.setState, StateReady, StateDisconnecting, true)
	assertStateTransition(t, e, e.setState, StateReady, StateDisconnected, false)

	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateWaitingForIdentity, false)
	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateReady, false)
	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateWaitingToRegenerate, false)
	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateDisconnecting, true)
	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateDisconnected, false)

	assertStateTransition(t, e, e.setState, StateRegenerating, StateWaitingForIdentity, true)
	assertStateTransition(t, e, e.setState, StateRegenerating, StateReady, false)
	assertStateTransition(t, e, e.setState, StateRegenerating, StateWaitingToRegenerate, true)
	assertStateTransition(t, e, e.setState, StateRegenerating, StateRegenerating, false)
	assertStateTransition(t, e, e.setState, StateRegenerating, StateDisconnecting, true)
	assertStateTransition(t, e, e.setState, StateRegenerating, StateDisconnected, false)

	assertStateTransition(t, e, e.setState, StateDisconnecting, StateWaitingForIdentity, false)
	assertStateTransition(t, e, e.setState, StateDisconnecting, StateReady, false)
	assertStateTransition(t, e, e.setState, StateDisconnecting, StateWaitingToRegenerate, false)
	assertStateTransition(t, e, e.setState, StateDisconnecting, StateRegenerating, false)
	assertStateTransition(t, e, e.setState, StateDisconnecting, StateDisconnecting, false)
	assertStateTransition(t, e, e.setState, StateDisconnecting, StateDisconnected, true)

	assertStateTransition(t, e, e.setState, StateDisconnected, StateWaitingForIdentity, false)
	assertStateTransition(t, e, e.setState, StateDisconnected, StateReady, false)
	assertStateTransition(t, e, e.setState, StateDisconnected, StateWaitingToRegenerate, false)
	assertStateTransition(t, e, e.setState, StateDisconnected, StateRegenerating, false)
	assertStateTransition(t, e, e.setState, StateDisconnected, StateDisconnecting, false)
	assertStateTransition(t, e, e.setState, StateDisconnected, StateDisconnected, false)

	// State transitions involving the "Invalid" state
	assertStateTransition(t, e, e.setState, "", StateInvalid, false)
	assertStateTransition(t, e, e.setState, StateWaitingForIdentity, StateInvalid, true)
	assertStateTransition(t, e, e.setState, StateInvalid, StateInvalid, false)

	// Builder-specific transitions

	// Builder can't transition to ready from waiting-to-regenerate
	// as (another) build is pending
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateReady, false)
	// Only builder knows when bpf regeneration starts
	assertStateTransition(t, e, e.setState, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)

	// Builder does not trigger the need for regeneration
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateRegenerating, StateWaitingToRegenerate, false)
	// Builder transitions to ready state after build is done
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateRegenerating, StateReady, true)

	// Check that direct transition from restoring --> regenerating is valid.
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateRestoring, StateRegenerating, true)

	// Typical lifecycle
	assertStateTransition(t, e, e.setState, "", StateWaitingForIdentity, true)
	// Initial build does not change the state
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingForIdentity, StateRegenerating, false)
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingForIdentity, StateReady, false)
	// identity arrives
	assertStateTransition(t, e, e.setState, StateWaitingForIdentity, StateReady, true)
	// a build is triggered after the identity is set
	assertStateTransition(t, e, e.setState, StateReady, StateWaitingToRegenerate, true)
	// build starts
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)
	// another change arrives while building
	assertStateTransition(t, e, e.setState, StateRegenerating, StateWaitingToRegenerate, true)
	// Builder's transition to ready fails due to the queued build
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateReady, false)
	// second build starts
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)
	// second build finishes
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateRegenerating, StateReady, true)
	// endpoint is being deleted
	assertStateTransition(t, e, e.setState, StateReady, StateDisconnecting, true)
	// parallel disconnect fails
	assertStateTransition(t, e, e.setState, StateDisconnecting, StateDisconnecting, false)
	assertStateTransition(t, e, e.setState, StateDisconnecting, StateDisconnected, true)

	// Restoring state
	assertStateTransition(t, e, e.setState, StateRestoring, StateWaitingToRegenerate, false)
	assertStateTransition(t, e, e.setState, StateRestoring, StateDisconnecting, true)

	assertStateTransition(t, e, e.setState, StateRestoring, StateRestoring, true)

	// Invalid state
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateInvalid, StateReady, false)
	assertStateTransition(t, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateInvalid, false)
}

func assertStateTransition(t *testing.T,
	e *Endpoint, stateSetter func(toState State, reason string) bool,
	from, to State,
	success bool) {

	e.state = from

	currStateOldMetric := getMetricValue(e.state)
	newStateOldMetric := getMetricValue(to)
	got := stateSetter(to, "test")
	currStateNewMetric := getMetricValue(from)
	newStateNewMetric := getMetricValue(e.state)

	require.Equal(t, success, got)

	// Do not assert on metrics if the endpoint is not expected to transition.
	if !success {
		return
	}

	// If the state transition moves from itself to itself, we expect the
	// metrics to be unchanged.
	if from == to {
		require.Equal(t, currStateNewMetric, currStateOldMetric)
		require.Equal(t, newStateNewMetric, newStateOldMetric)
	} else {
		// Blank states don't have metrics so we skip over that; metric should
		// be unchanged.
		if from != "" {
			require.Equal(t, currStateNewMetric, currStateOldMetric-1)
		} else {
			require.Equal(t, currStateNewMetric, currStateOldMetric)
		}

		// Don't assert on state transition that ends up in a final state, as
		// the metric is not incremented in this case; metric should be
		// unchanged.
		if !isFinalState(to) {
			require.Equal(t, newStateNewMetric, newStateOldMetric+1)
		} else {
			require.Equal(t, newStateNewMetric, newStateOldMetric)
		}
	}
}

func isFinalState(state State) bool {
	return state == StateDisconnected || state == StateInvalid
}

func getMetricValue(state State) int64 {
	return int64(metrics.GetGaugeValue(metrics.EndpointStateCount.WithLabelValues(string(state))))
}

func TestWaitForPolicyRevision(t *testing.T) {
	setupEndpointSuite(t)

	e := &Endpoint{policyRevision: 0}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1*time.Second))

	cbRan := false
	<-e.WaitForPolicyRevision(ctx, 0, func(time.Time) { cbRan = true })
	// shouldn't get a timeout when waiting for policy revision already reached
	require.Nil(t, ctx.Err())
	// Should see a callback when waiting for a policy revision already reached
	require.Equal(t, true, cbRan)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithTimeout(context.Background(), time.Duration(1*time.Second))
	cbRan = false

	<-e.WaitForPolicyRevision(ctx, 0, func(time.Time) { cbRan = true })
	// shouldn't get a timeout when waiting for policy revision already reached
	require.Nil(t, ctx.Err())
	// Should see a callback because the channel returned
	require.Equal(t, true, cbRan)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithCancel(context.Background())
	cbRan = false

	ch := e.WaitForPolicyRevision(ctx, 2, func(time.Time) { cbRan = true })
	cancel()
	// context was prematurely closed on purpose the error should be nil
	require.Equal(t, context.Canceled, ctx.Err())
	// Should not see a callback when we don't close the channel
	require.Equal(t, false, cbRan)

	e.setPolicyRevision(3)

	select {
	case <-ch:
	default:
		t.Fatalf("channel should have been closed since the wanted policy revision was reached")
	}

	// Number of policy revision signals should be 0
	require.Equal(t, 0, len(e.policyRevisionSignals))

	e.state = StateDisconnected

	ctx, cancel = context.WithCancel(context.Background())
	cbRan = false
	ch = e.WaitForPolicyRevision(ctx, 99, func(time.Time) { cbRan = true })
	cancel()
	select {
	case <-ch:
	default:
		t.Fatalf("channel should have been closed since the endpoint is in disconnected state")
	}
	// Should see a callback because the channel was closed
	require.Equal(t, true, cbRan)

	// Number of policy revision signals should be 0
	require.Equal(t, 0, len(e.policyRevisionSignals))

	e.state = StateWaitingForIdentity
	ctx, cancel = context.WithCancel(context.Background())
	ch = e.WaitForPolicyRevision(ctx, 99, func(time.Time) { cbRan = true })

	e.cleanPolicySignals()

	select {
	case <-ch:
	default:
		t.Fatalf("channel should have been closed since all policy signals were closed")
	}
	// Should see a callback because the channel was closed
	require.Equal(t, true, cbRan)
	cancel()

	// Number of policy revision signals should be 0
	require.Equal(t, 0, len(e.policyRevisionSignals))
}

func TestProxyID(t *testing.T) {
	setupEndpointSuite(t)

	e := &Endpoint{ID: 123, policyRevision: 0}
	e.UpdateLogger(nil)

	id, port, proto := e.proxyID(&policy.L4Filter{Port: 8080, Protocol: api.ProtoTCP, Ingress: true}, "")
	require.NotEqual(t, "", id)
	require.Equal(t, uint16(8080), port)
	require.Equal(t, uint8(6), proto)

	endpointID, ingress, protocol, port, listener, err := policy.ParseProxyID(id)
	require.Equal(t, uint16(123), endpointID)
	require.Equal(t, true, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(8080), port)
	require.Equal(t, "", listener)
	require.Nil(t, err)

	id, port, proto = e.proxyID(&policy.L4Filter{Port: 8080, Protocol: api.ProtoTCP, Ingress: true, L7Parser: policy.ParserTypeCRD}, "test-listener")
	require.NotEqual(t, "", id)
	require.Equal(t, uint16(8080), port)
	require.Equal(t, uint8(6), proto)
	endpointID, ingress, protocol, port, listener, err = policy.ParseProxyID(id)
	require.Equal(t, uint16(123), endpointID)
	require.Equal(t, true, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(8080), port)
	require.Equal(t, "test-listener", listener)
	require.Nil(t, err)

	// Undefined named port
	id, port, proto = e.proxyID(&policy.L4Filter{PortName: "foobar", Protocol: api.ProtoTCP, Ingress: true}, "")
	require.Equal(t, "", id)
	require.Equal(t, uint16(0), port)
	require.Equal(t, uint8(0), proto)
}

func TestEndpoint_GetK8sPodLabels(t *testing.T) {
	type fields struct {
		OpLabels labels.OpLabels
	}
	tests := []struct {
		name   string
		fields fields
		want   labels.Labels
	}{
		{
			name: "has all k8s labels",
			fields: fields{
				OpLabels: labels.OpLabels{
					OrchestrationInfo: labels.Map2Labels(map[string]string{"foo": "bar"}, labels.LabelSourceK8s),
				},
			},
			want: labels.Map2Labels(map[string]string{"foo": "bar"}, labels.LabelSourceK8s),
		},
		{
			name: "the namespace labels, service account and namespace should be ignored as they don't belong to pod labels",
			fields: fields{
				OpLabels: labels.OpLabels{
					OrchestrationInfo: labels.Map2Labels(map[string]string{
						"foo":                                    "bar",
						ciliumio.PodNamespaceMetaLabels + ".env": "prod",
						ciliumio.PolicyLabelServiceAccount:       "default",
						ciliumio.PodNamespaceLabel:               "default",
					}, labels.LabelSourceK8s),
				},
			},
			want: labels.Map2Labels(map[string]string{"foo": "bar"}, labels.LabelSourceK8s),
		},
		{
			name: "labels with other source than k8s should also be ignored",
			fields: fields{
				OpLabels: labels.OpLabels{
					OrchestrationInfo: labels.Map2Labels(map[string]string{
						"foo":                                    "bar",
						ciliumio.PodNamespaceMetaLabels + ".env": "prod",
					}, labels.LabelSourceK8s),
					OrchestrationIdentity: labels.Map2Labels(map[string]string{
						"foo2":                                   "bar",
						ciliumio.PodNamespaceMetaLabels + ".env": "prod2",
					}, labels.LabelSourceAny),
				},
			},
			want: labels.Map2Labels(map[string]string{"foo": "bar"}, labels.LabelSourceK8s),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{
				mutex:    lock.RWMutex{},
				OpLabels: tt.fields.OpLabels,
			}
			if got := e.getK8sPodLabels(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Endpoint.getK8sPodLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestK8sPodNameIsSet(t *testing.T) {
	e := Endpoint{}
	require.Equal(t, false, e.K8sNamespaceAndPodNameIsSet())
	e.K8sPodName = "foo"
	e.K8sNamespace = "default"
	require.Equal(t, true, e.K8sNamespaceAndPodNameIsSet())
}

type EndpointDeadlockEvent struct {
	ep           *Endpoint
	deadlockChan chan struct{}
}

var (
	deadlockTimeout     = 2 * time.Second
	deadlockTestTimeout = 3*deadlockTimeout + 1*time.Second
)

func (n *EndpointDeadlockEvent) Handle(ifc chan interface{}) {
	// We need to sleep here so that we are consuming an event off the queue,
	// but not acquiring the lock yet.
	// There isn't much of a better way to ensure that an Event is being
	// processed off of the EventQueue, but hasn't acquired the Endpoint's
	// lock *before* we call deleteEndpointQuiet (see below test).
	close(n.deadlockChan)
	time.Sleep(deadlockTimeout)
	n.ep.unconditionalLock()
	n.ep.unlock()
}

// This unit test is a bit weird - see
// https://github.com/cilium/cilium/pull/8687 .
func TestEndpointEventQueueDeadlockUponStop(t *testing.T) {
	s := setupEndpointSuite(t)

	// Need to modify global configuration (hooray!), change back when test is
	// done.
	oldQueueSize := option.Config.EndpointQueueSize
	option.Config.EndpointQueueSize = 1
	defer func() {
		option.Config.EndpointQueueSize = oldQueueSize
	}()

	oldDatapath := s.datapath

	s.datapath = fakeTypes.NewDatapath()

	defer func() {
		s.datapath = oldDatapath
	}()

	ep := NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)

	ep.properties[PropertyFakeEndpoint] = true
	ep.properties[PropertySkipBPFPolicy] = true

	// In case deadlock occurs, provide a timeout of 3 (number of events) *
	// deadlockTimeout + 1 seconds to ensure that we are actually testing for
	// deadlock, and not prematurely exiting, and also so the test suite doesn't
	// hang forever.
	ctx, cancel := context.WithTimeout(context.Background(), deadlockTestTimeout)
	defer cancel()

	// Create three events that go on the endpoint's EventQueue. We need three
	// events because the first event enqueued immediately is consumed off of
	// the queue; the second event is put onto the queue (which has length of
	// one), and the third queue is waiting for the queue's buffer to not be
	// full (e.g., the first event is finished processing). If the first event
	// gets stuck processing forever due to deadlock, then the third event
	// will never be consumed, and the endpoint's EventQueue will never be
	// closed because Enqueue gets stuck.
	ev1Ch := make(chan struct{})
	ev2Ch := make(chan struct{})
	ev3Ch := make(chan struct{})

	ev := eventqueue.NewEvent(&EndpointDeadlockEvent{
		ep:           ep,
		deadlockChan: ev1Ch,
	})

	ev2 := eventqueue.NewEvent(&EndpointDeadlockEvent{
		ep:           ep,
		deadlockChan: ev2Ch,
	})

	ev3 := eventqueue.NewEvent(&EndpointDeadlockEvent{
		ep:           ep,
		deadlockChan: ev3Ch,
	})

	ev2EnqueueCh := make(chan struct{})

	go func() {
		_, err := ep.eventQueue.Enqueue(ev)
		require.Nil(t, err)
		_, err = ep.eventQueue.Enqueue(ev2)
		require.Nil(t, err)
		close(ev2EnqueueCh)
		_, err = ep.eventQueue.Enqueue(ev3)
		require.Nil(t, err)
	}()

	// Ensure that the second event is enqueued before proceeding further, as
	// we need to assume that at least one event is being processed, and another
	// one is pushed onto the endpoint's EventQueue.
	<-ev2EnqueueCh
	epStopComplete := make(chan struct{})

	// Launch endpoint deletion async so that we do not deadlock (which is what
	// this unit test is designed to test).
	go func(ch chan struct{}) {
		ep.Stop()
		epStopComplete <- struct{}{}
	}(epStopComplete)

	select {
	case <-ctx.Done():
		t.Log("endpoint deletion did not complete in time")
		t.Fail()
	case <-epStopComplete:
		// Success, do nothing.
	}
}

func BenchmarkEndpointGetModel(b *testing.B) {
	s := setupEndpointSuite(b)

	e := NewTestEndpointWithState(b, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 123, StateWaitingForIdentity)

	for i := 0; i < 256; i++ {
		e.LogStatusOK(BPF, "Hello World!")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.GetModel()
	}
}

// getK8sPodLabels returns all labels that exist in the endpoint and were
// derived from k8s pod.
func (e *Endpoint) getK8sPodLabels() labels.Labels {
	e.unconditionalRLock()
	defer e.runlock()
	allLabels := e.OpLabels.AllLabels()
	if allLabels == nil {
		return nil
	}

	allLabelsFromK8s := allLabels.GetFromSource(labels.LabelSourceK8s)

	k8sEPPodLabels := labels.Labels{}
	for k, v := range allLabelsFromK8s {
		if !strings.HasPrefix(v.Key, ciliumio.PodNamespaceMetaLabels) &&
			!strings.HasPrefix(v.Key, ciliumio.PolicyLabelServiceAccount) &&
			!strings.HasPrefix(v.Key, ciliumio.PodNamespaceLabel) {
			k8sEPPodLabels[k] = v
		}
	}
	return k8sEPPodLabels
}
