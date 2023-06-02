// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/datapath/fake"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/types"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointSuite struct {
	regeneration.Owner
	repo     *policy.Repository
	datapath datapath.Datapath
	mgr      fakeIdentityAllocator

	// Owners interface mock
	OnGetPolicyRepository     func() *policy.Repository
	OnGetNamedPorts           func() (npm types.NamedPortMultiMap)
	OnQueueEndpointBuild      func(ctx context.Context, epID uint64) (func(), error)
	OnRemoveFromEndpointQueue func(epID uint64)
	OnGetCompilationLock      func() *lock.RWMutex
	OnSendNotification        func(msg monitorAPI.AgentNotifyMessage) error

	// Metrics
	collectors []prometheus.Collector
}

// suite can be used by testing.T benchmarks or tests as a mock regeneration.Owner
var suite = EndpointSuite{repo: policy.NewPolicyRepository(nil, nil, nil, nil)}
var _ = Suite(&suite)

func (s *EndpointSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)

	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
	s.repo = policy.NewPolicyRepository(nil, nil, nil, nil)
	// GetConfig the default labels prefix filter
	err := labelsfilter.ParseLabelPrefixCfg(nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}

	// Register metrics once before running the suite
	_, s.collectors = metrics.CreateConfiguration([]string{"cilium_endpoint_state"})
	metrics.MustRegister(s.collectors...)
}

func (s *EndpointSuite) TearDownSuite(c *C) {
	// Unregister the metrics after the suite has finished
	for _, c := range s.collectors {
		metrics.Unregister(c)
	}
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

func (s *EndpointSuite) GetCompilationLock() *lock.RWMutex {
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

// TODO: Remove the etcd dependency from these tests with a full dummy
// implementation of an identity allocator under pkg/testutils/identity.
// Until we do that, these tests must rely on the real CachingIdentityAllocator
// implementation inside.
type fakeIdentityAllocator struct {
	*cache.CachingIdentityAllocator
}

func (f fakeIdentityAllocator) AllocateCIDRsForIPs([]net.IP, map[netip.Prefix]*identity.Identity) ([]*identity.Identity, error) {
	return nil, nil
}

func (f fakeIdentityAllocator) ReleaseCIDRIdentitiesByID(context.Context, []identity.NumericIdentity) {
}

func NewCachingIdentityAllocator(owner cache.IdentityAllocatorOwner) fakeIdentityAllocator {
	return fakeIdentityAllocator{
		CachingIdentityAllocator: cache.NewCachingIdentityAllocator(owner),
	}
}

// func (f *fakeIdentityAllocator)

func (s *EndpointSuite) SetUpTest(c *C) {
	/* Required to test endpoint CEP policy model */
	kvstore.SetupDummy("etcd")
	identity.InitWellKnownIdentities(&fakeConfig.Config{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	<-mgr.InitIdentityAllocator(nil)
	s.mgr = mgr
}

func (s *EndpointSuite) TearDownTest(c *C) {
	s.mgr.Close()
	kvstore.Client().Close(context.TODO())
}

func (s *EndpointSuite) TestEndpointStatus(c *C) {
	eps := NewEndpointStatus()

	c.Assert(eps.String(), Equals, "OK")

	sts := &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "BPF Program compiled",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "OK")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "BPF Program failed to compile",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

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
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

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
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "OK")
}

func (s *EndpointSuite) TestEndpointUpdateLabels(c *C) {
	e := NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 100, StateWaitingForIdentity)

	// Test that inserting identity labels works
	rev := e.replaceIdentityLabels(labels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(rev, Not(Equals), 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Test that nothing changes
	rev = e.replaceIdentityLabels(labels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(rev, Equals, 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Remove one label, change the source and value of the other.
	rev = e.replaceIdentityLabels(labels.Map2Labels(map[string]string{"foo": "zop"}, "nginx"))
	c.Assert(rev, Not(Equals), 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "nginx:foo=zop;")

	// Test that inserting information labels works
	e.replaceInformationLabels(labels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(string(e.OpLabels.OrchestrationInfo.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Remove one label, change the source and value of the other.
	e.replaceInformationLabels(labels.Map2Labels(map[string]string{"foo": "zop"}, "nginx"))
	c.Assert(string(e.OpLabels.OrchestrationInfo.SortedList()), Equals, "nginx:foo=zop;")
}

func (s *EndpointSuite) TestEndpointState(c *C) {
	e := NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 100, StateWaitingForIdentity)
	e.unconditionalLock()
	defer e.unlock()

	assertStateTransition(c, e, e.setState, StateWaitingForIdentity, StateWaitingForIdentity, false)

	assertStateTransition(c, e, e.setState, StateWaitingForIdentity, StateReady, true)

	assertStateTransition(c, e, e.setState, StateWaitingForIdentity, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(c, e, e.setState, StateRegenerating, StateDisconnecting, true)

	assertStateTransition(c, e, e.setState, StateWaitingForIdentity, StateDisconnected, false)

	assertStateTransition(c, e, e.setState, StateReady, StateWaitingForIdentity, true)
	assertStateTransition(c, e, e.setState, StateReady, StateReady, false)
	assertStateTransition(c, e, e.setState, StateReady, StateWaitingToRegenerate, true)
	assertStateTransition(c, e, e.setState, StateReady, StateRegenerating, false)
	assertStateTransition(c, e, e.setState, StateReady, StateDisconnecting, true)
	assertStateTransition(c, e, e.setState, StateReady, StateDisconnected, false)

	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateWaitingForIdentity, false)
	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateReady, false)
	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateDisconnecting, true)
	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateDisconnected, false)

	assertStateTransition(c, e, e.setState, StateRegenerating, StateWaitingForIdentity, true)
	assertStateTransition(c, e, e.setState, StateRegenerating, StateReady, false)
	assertStateTransition(c, e, e.setState, StateRegenerating, StateWaitingToRegenerate, true)
	assertStateTransition(c, e, e.setState, StateRegenerating, StateRegenerating, false)
	assertStateTransition(c, e, e.setState, StateRegenerating, StateDisconnecting, true)
	assertStateTransition(c, e, e.setState, StateRegenerating, StateDisconnected, false)

	assertStateTransition(c, e, e.setState, StateDisconnecting, StateWaitingForIdentity, false)
	assertStateTransition(c, e, e.setState, StateDisconnecting, StateReady, false)
	assertStateTransition(c, e, e.setState, StateDisconnecting, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.setState, StateDisconnecting, StateRegenerating, false)
	assertStateTransition(c, e, e.setState, StateDisconnecting, StateDisconnecting, false)
	assertStateTransition(c, e, e.setState, StateDisconnecting, StateDisconnected, true)

	assertStateTransition(c, e, e.setState, StateDisconnected, StateWaitingForIdentity, false)
	assertStateTransition(c, e, e.setState, StateDisconnected, StateReady, false)
	assertStateTransition(c, e, e.setState, StateDisconnected, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.setState, StateDisconnected, StateRegenerating, false)
	assertStateTransition(c, e, e.setState, StateDisconnected, StateDisconnecting, false)
	assertStateTransition(c, e, e.setState, StateDisconnected, StateDisconnected, false)

	// State transitions involving the "Invalid" state
	assertStateTransition(c, e, e.setState, "", StateInvalid, false)
	assertStateTransition(c, e, e.setState, StateWaitingForIdentity, StateInvalid, true)
	assertStateTransition(c, e, e.setState, StateInvalid, StateInvalid, false)

	// Builder-specific transitions

	// Builder can't transition to ready from waiting-to-regenerate
	// as (another) build is pending
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateReady, false)
	// Only builder knows when bpf regeneration starts
	assertStateTransition(c, e, e.setState, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)

	// Builder does not trigger the need for regeneration
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRegenerating, StateWaitingToRegenerate, false)
	// Builder transitions to ready state after build is done
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRegenerating, StateReady, true)

	// Check that direct transition from restoring --> regenerating is valid.
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRestoring, StateRegenerating, true)

	// Typical lifecycle
	assertStateTransition(c, e, e.setState, "", StateWaitingForIdentity, true)
	// Initial build does not change the state
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingForIdentity, StateRegenerating, false)
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingForIdentity, StateReady, false)
	// identity arrives
	assertStateTransition(c, e, e.setState, StateWaitingForIdentity, StateReady, true)
	// a build is triggered after the identity is set
	assertStateTransition(c, e, e.setState, StateReady, StateWaitingToRegenerate, true)
	// build starts
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)
	// another change arrives while building
	assertStateTransition(c, e, e.setState, StateRegenerating, StateWaitingToRegenerate, true)
	// Builder's transition to ready fails due to the queued build
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateReady, false)
	// second build starts
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)
	// second build finishes
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRegenerating, StateReady, true)
	// endpoint is being deleted
	assertStateTransition(c, e, e.setState, StateReady, StateDisconnecting, true)
	// parallel disconnect fails
	assertStateTransition(c, e, e.setState, StateDisconnecting, StateDisconnecting, false)
	assertStateTransition(c, e, e.setState, StateDisconnecting, StateDisconnected, true)

	// Restoring state
	assertStateTransition(c, e, e.setState, StateRestoring, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.setState, StateRestoring, StateDisconnecting, true)

	assertStateTransition(c, e, e.setState, StateRestoring, StateRestoring, true)

	// Invalid state
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateInvalid, StateReady, false)
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateInvalid, false)
}

func assertStateTransition(c *C,
	e *Endpoint, stateSetter func(toState State, reason string) bool,
	from, to State,
	success bool) {

	e.state = from

	currStateOldMetric := getMetricValue(e.state)
	newStateOldMetric := getMetricValue(to)
	got := stateSetter(to, "test")
	currStateNewMetric := getMetricValue(from)
	newStateNewMetric := getMetricValue(e.state)

	c.Assert(got, Equals, success)

	// Do not assert on metrics if the endpoint is not expected to transition.
	if !success {
		return
	}

	// If the state transition moves from itself to itself, we expect the
	// metrics to be unchanged.
	if from == to {
		c.Assert(currStateOldMetric, Equals, currStateNewMetric)
		c.Assert(newStateOldMetric, Equals, newStateNewMetric)
	} else {
		// Blank states don't have metrics so we skip over that; metric should
		// be unchanged.
		if from != "" {
			c.Assert(currStateOldMetric-1, Equals, currStateNewMetric)
		} else {
			c.Assert(currStateOldMetric, Equals, currStateNewMetric)
		}

		// Don't assert on state transition that ends up in a final state, as
		// the metric is not incremented in this case; metric should be
		// unchanged.
		if !isFinalState(to) {
			c.Assert(newStateOldMetric+1, Equals, newStateNewMetric)
		} else {
			c.Assert(newStateOldMetric, Equals, newStateNewMetric)
		}
	}
}

func isFinalState(state State) bool {
	return state == StateDisconnected || state == StateInvalid
}

func getMetricValue(state State) int64 {
	return int64(metrics.GetGaugeValue(metrics.EndpointStateCount.WithLabelValues(string(state))))
}

func (s *EndpointSuite) TestWaitForPolicyRevision(c *C) {
	e := &Endpoint{policyRevision: 0}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1*time.Second))

	cbRan := false
	<-e.WaitForPolicyRevision(ctx, 0, func(time.Time) { cbRan = true })
	// shouldn't get a timeout when waiting for policy revision already reached
	c.Assert(ctx.Err(), IsNil)
	// Should see a callback when waiting for a policy revision already reached
	c.Assert(cbRan, Equals, true)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithTimeout(context.Background(), time.Duration(1*time.Second))
	cbRan = false

	<-e.WaitForPolicyRevision(ctx, 0, func(time.Time) { cbRan = true })
	// shouldn't get a timeout when waiting for policy revision already reached
	c.Assert(ctx.Err(), IsNil)
	// Should see a callback because the channel returned
	c.Assert(cbRan, Equals, true)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithCancel(context.Background())
	cbRan = false

	ch := e.WaitForPolicyRevision(ctx, 2, func(time.Time) { cbRan = true })
	cancel()
	// context was prematurely closed on purpose the error should be nil
	c.Assert(ctx.Err(), Equals, context.Canceled)
	// Should not see a callback when we don't close the channel
	c.Assert(cbRan, Equals, false)

	e.setPolicyRevision(3)

	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since the wanted policy revision was reached")
	}

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)

	e.state = StateDisconnected

	ctx, cancel = context.WithCancel(context.Background())
	cbRan = false
	ch = e.WaitForPolicyRevision(ctx, 99, func(time.Time) { cbRan = true })
	cancel()
	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since the endpoint is in disconnected state")
	}
	// Should see a callback because the channel was closed
	c.Assert(cbRan, Equals, true)

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)

	e.state = StateWaitingForIdentity
	ctx, cancel = context.WithCancel(context.Background())
	ch = e.WaitForPolicyRevision(ctx, 99, func(time.Time) { cbRan = true })

	e.cleanPolicySignals()

	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since all policy signals were closed")
	}
	// Should see a callback because the channel was closed
	c.Assert(cbRan, Equals, true)
	cancel()

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)
}

func (s *EndpointSuite) TestProxyID(c *C) {
	e := &Endpoint{ID: 123, policyRevision: 0}

	id := e.proxyID(&policy.L4Filter{Port: 8080, Protocol: api.ProtoTCP, Ingress: true})
	c.Assert(id, Not(Equals), "")
	endpointID, ingress, protocol, port, err := policy.ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(123))
	c.Assert(ingress, Equals, true)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(8080))
	c.Assert(err, IsNil)
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

func (s *EndpointSuite) TestK8sPodNameIsSet(c *C) {
	e := Endpoint{}
	c.Assert(e.K8sNamespaceAndPodNameIsSet(), Equals, false)
	e.K8sPodName = "foo"
	e.K8sNamespace = "default"
	c.Assert(e.K8sNamespaceAndPodNameIsSet(), Equals, true)
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
func (s *EndpointSuite) TestEndpointEventQueueDeadlockUponStop(c *C) {
	// Need to modify global configuration (hooray!), change back when test is
	// done.
	oldQueueSize := option.Config.EndpointQueueSize
	oldDryMode := option.Config.DryMode
	option.Config.EndpointQueueSize = 1
	option.Config.DryMode = true
	defer func() {
		option.Config.EndpointQueueSize = oldQueueSize
		option.Config.DryMode = oldDryMode
	}()

	oldDatapath := s.datapath

	s.datapath = fake.NewDatapath()

	defer func() {
		s.datapath = oldDatapath
	}()

	ep := NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)

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
		c.Assert(err, IsNil)
		_, err = ep.eventQueue.Enqueue(ev2)
		c.Assert(err, IsNil)
		close(ev2EnqueueCh)
		_, err = ep.eventQueue.Enqueue(ev3)
		c.Assert(err, IsNil)
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
		c.Log("endpoint deletion did not complete in time")
		c.Fail()
	case <-epStopComplete:
		// Success, do nothing.
	}
}

func BenchmarkEndpointGetModel(b *testing.B) {
	e := NewEndpointWithState(&suite, &suite, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 123, StateWaitingForIdentity)

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
