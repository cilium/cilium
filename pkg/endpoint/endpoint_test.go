// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package endpoint

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/kvstore"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/revert"

	"github.com/prometheus/client_golang/prometheus"
	. "gopkg.in/check.v1"
)

var (
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointSuite struct {
	repo *policy.Repository

	// Metrics
	collectors []prometheus.Collector
}

// suite can be used by testing.T benchmarks or tests as a mock regeneration.Owner
var suite = EndpointSuite{repo: policy.NewPolicyRepository()}
var _ = Suite(&suite)

func (s *EndpointSuite) SetUpSuite(c *C) {
	s.repo = policy.NewPolicyRepository()

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

func (s *EndpointSuite) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, wg *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	return 0, nil, nil, nil
}

func (s *EndpointSuite) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

func (s *EndpointSuite) UpdateNetworkPolicy(e regeneration.EndpointUpdater, policy *policy.L4Policy,
	proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	return nil, nil
}

func (s *EndpointSuite) RemoveNetworkPolicy(e regeneration.EndpointInfoSource) {}

func (s *EndpointSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *EndpointSuite) RemoveFromEndpointQueue(epID uint64) {}

func (s *EndpointSuite) GetCompilationLock() *lock.RWMutex {
	return nil
}

func (s *EndpointSuite) SendNotification(typ monitorAPI.AgentNotification, text string) error {
	return nil
}

func (s *EndpointSuite) Datapath() datapath.Datapath {
	return nil
}

func (s *EndpointSuite) GetNodeSuffix() string {
	return ""
}

func (s *EndpointSuite) UpdateIdentities(added, deleted cache.IdentityCache) {}

type testIdentityAllocator struct{}

func (t *testIdentityAllocator) UpdateIdentities(added, deleted cache.IdentityCache) {}

func (t *testIdentityAllocator) GetNodeSuffix() string { return "foo" }

func (s *EndpointSuite) SetUpTest(c *C) {
	/* Required to test endpoint CEP policy model */
	kvstore.SetupDummy("etcd")
	identity.InitWellKnownIdentities()
	// The nils are only used by k8s CRD identities. We default to kvstore.
	<-cache.InitIdentityAllocator(&testIdentityAllocator{}, nil, nil)
}

func (s *EndpointSuite) TearDownTest(c *C) {
	cache.Close()
	kvstore.Client().Close()
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
	e := NewEndpointWithState(s, 100, StateCreating)

	// Test that inserting identity labels works
	rev := e.replaceIdentityLabels(pkgLabels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(rev, Not(Equals), 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Test that nothing changes
	rev = e.replaceIdentityLabels(pkgLabels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(rev, Equals, 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Remove one label, change the source and value of the other.
	rev = e.replaceIdentityLabels(pkgLabels.Map2Labels(map[string]string{"foo": "zop"}, "nginx"))
	c.Assert(rev, Not(Equals), 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "nginx:foo=zop;")

	// Test that inserting information labels works
	e.replaceInformationLabels(pkgLabels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(string(e.OpLabels.OrchestrationInfo.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Remove one label, change the source and value of the other.
	e.replaceInformationLabels(pkgLabels.Map2Labels(map[string]string{"foo": "zop"}, "nginx"))
	c.Assert(string(e.OpLabels.OrchestrationInfo.SortedList()), Equals, "nginx:foo=zop;")
}

func (s *EndpointSuite) TestEndpointState(c *C) {
	e := NewEndpointWithState(s, 100, StateCreating)
	e.UnconditionalLock()
	defer e.Unlock()

	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateCreating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateWaitingForIdentity, true)
	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateReady, false)
	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateRegenerating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateDisconnecting, true)
	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateDisconnected, false)

	assertStateTransition(c, e, e.SetStateLocked, StateWaitingForIdentity, StateCreating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingForIdentity, StateWaitingForIdentity, false)

	assertStateTransition(c, e, e.SetStateLocked, StateWaitingForIdentity, StateReady, true)

	assertStateTransition(c, e, e.SetStateLocked, StateWaitingForIdentity, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateDisconnecting, true)

	assertStateTransition(c, e, e.SetStateLocked, StateWaitingForIdentity, StateDisconnected, false)

	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateCreating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateWaitingForIdentity, true)
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateReady, false)
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateWaitingToRegenerate, true)
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateRegenerating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateDisconnecting, true)
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateDisconnected, false)

	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateCreating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateWaitingForIdentity, true)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateReady, false)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateDisconnecting, true)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateDisconnected, false)

	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateCreating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateWaitingForIdentity, true)
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateReady, false)
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateWaitingToRegenerate, true)
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateRegenerating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateDisconnecting, true)
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateDisconnected, false)

	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateCreating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateWaitingForIdentity, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateReady, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateRegenerating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateDisconnecting, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateDisconnected, true)

	assertStateTransition(c, e, e.SetStateLocked, StateDisconnected, StateCreating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnected, StateWaitingForIdentity, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnected, StateReady, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnected, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnected, StateRegenerating, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnected, StateDisconnecting, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnected, StateDisconnected, false)

	// State transitions involving the "Invalid" state
	assertStateTransition(c, e, e.SetStateLocked, "", StateInvalid, false)
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingForIdentity, StateInvalid, true)
	assertStateTransition(c, e, e.SetStateLocked, StateInvalid, StateInvalid, false)

	// Builder-specific transitions

	// Builder can't transition to ready from waiting-to-regenerate
	// as (another) build is pending
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateReady, false)
	// Only builder knows when bpf regeneration starts
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingToRegenerate, StateRegenerating, false)
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)

	// Builder does not trigger the need for regeneration
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRegenerating, StateWaitingToRegenerate, false)
	// Builder transitions to ready state after build is done
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRegenerating, StateReady, true)

	// Check that direct transition from restoring --> regenerating is valid.
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRestoring, StateRegenerating, true)

	// Typical lifecycle
	assertStateTransition(c, e, e.SetStateLocked, StateCreating, StateWaitingForIdentity, true)
	assertStateTransition(c, e, e.SetStateLocked, "", StateWaitingForIdentity, true)
	// Initial build does not change the state
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingForIdentity, StateRegenerating, false)
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingForIdentity, StateReady, false)
	// identity arrives
	assertStateTransition(c, e, e.SetStateLocked, StateWaitingForIdentity, StateReady, true)
	// a build is triggered after the identity is set
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateWaitingToRegenerate, true)
	// build starts
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)
	// another change arrives while building
	assertStateTransition(c, e, e.SetStateLocked, StateRegenerating, StateWaitingToRegenerate, true)
	// Builder's transition to ready fails due to the queued build
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateReady, false)
	// second build starts
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateRegenerating, true)
	// second build finishes
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateRegenerating, StateReady, true)
	// endpoint is being deleted
	assertStateTransition(c, e, e.SetStateLocked, StateReady, StateDisconnecting, true)
	// parallel disconnect fails
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateDisconnecting, false)
	assertStateTransition(c, e, e.SetStateLocked, StateDisconnecting, StateDisconnected, true)

	// Restoring state
	assertStateTransition(c, e, e.SetStateLocked, StateRestoring, StateWaitingToRegenerate, false)
	assertStateTransition(c, e, e.SetStateLocked, StateRestoring, StateDisconnecting, true)

	assertStateTransition(c, e, e.SetStateLocked, StateRestoring, StateRestoring, true)

	// Invalid state
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateInvalid, StateReady, false)
	assertStateTransition(c, e, e.BuilderSetStateLocked, StateWaitingToRegenerate, StateInvalid, false)
}

func assertStateTransition(c *C,
	e *Endpoint, stateSetter func(string, string) bool,
	from, to string,
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

func isFinalState(state string) bool {
	return (state == StateDisconnected || state == StateInvalid)
}

func getMetricValue(state string) int64 {
	return int64(metrics.GetGaugeValue(metrics.EndpointStateCount.WithLabelValues(state)))
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

	e.state = StateCreating
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

	id := e.ProxyID(&policy.L4Filter{Port: 8080, Protocol: api.ProtoTCP, Ingress: true})
	endpointID, ingress, protocol, port, err := policy.ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(123))
	c.Assert(ingress, Equals, true)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(8080))
	c.Assert(err, IsNil)
}

func TestEndpoint_GetK8sPodLabels(t *testing.T) {
	type fields struct {
		OpLabels pkgLabels.OpLabels
	}
	tests := []struct {
		name   string
		fields fields
		want   pkgLabels.Labels
	}{
		{
			name: "has all k8s labels",
			fields: fields{
				OpLabels: pkgLabels.OpLabels{
					OrchestrationInfo: pkgLabels.Map2Labels(map[string]string{"foo": "bar"}, pkgLabels.LabelSourceK8s),
				},
			},
			want: pkgLabels.Map2Labels(map[string]string{"foo": "bar"}, pkgLabels.LabelSourceK8s),
		},
		{
			name: "the namespace labels, service account and namespace should be ignored as they don't belong to pod labels",
			fields: fields{
				OpLabels: pkgLabels.OpLabels{
					OrchestrationInfo: pkgLabels.Map2Labels(map[string]string{
						"foo":                                    "bar",
						ciliumio.PodNamespaceMetaLabels + ".env": "prod",
						ciliumio.PolicyLabelServiceAccount:       "default",
						ciliumio.PodNamespaceLabel:               "default",
					}, pkgLabels.LabelSourceK8s),
				},
			},
			want: pkgLabels.Map2Labels(map[string]string{"foo": "bar"}, pkgLabels.LabelSourceK8s),
		},
		{
			name: "labels with other source than k8s should also be ignored",
			fields: fields{
				OpLabels: pkgLabels.OpLabels{
					OrchestrationInfo: pkgLabels.Map2Labels(map[string]string{
						"foo":                                    "bar",
						ciliumio.PodNamespaceMetaLabels + ".env": "prod",
					}, pkgLabels.LabelSourceK8s),
					OrchestrationIdentity: pkgLabels.Map2Labels(map[string]string{
						"foo2":                                   "bar",
						ciliumio.PodNamespaceMetaLabels + ".env": "prod2",
					}, pkgLabels.LabelSourceAny),
				},
			},
			want: pkgLabels.Map2Labels(map[string]string{"foo": "bar"}, pkgLabels.LabelSourceK8s),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{
				mutex:    lock.RWMutex{},
				OpLabels: tt.fields.OpLabels,
			}
			if got := e.GetK8sPodLabels(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Endpoint.GetK8sPodLabels() = %v, want %v", got, tt.want)
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
