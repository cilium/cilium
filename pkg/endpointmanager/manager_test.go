// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	apiv1 "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

func (mgr *endpointManager) waitEndpointRemoved(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	mgr.unexpose(ep)
	ep.Stop()
	return nil
}

// RemoveAll removes all endpoints from the global maps.
func (mgr *endpointManager) RemoveAll(t testing.TB) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	mgr.epIDAllocator.reallocatePool(t)
	mgr.endpoints = map[uint16]*endpoint.Endpoint{}
	mgr.endpointsAux = map[string]*endpoint.Endpoint{}
}

// WaitEndpointRemoved waits until all operations associated with Remove of
// the endpoint have been completed.
// Note: only used for unit tests, to avoid ep.Delete()
func (mgr *endpointManager) WaitEndpointRemoved(ep *endpoint.Endpoint) {
	mgr.waitEndpointRemoved(ep, endpoint.DeleteConfig{})
}

type EndpointManagerSuite struct {
	repo *policy.Repository
}

var _ = Suite(&EndpointManagerSuite{})

func (s *EndpointManagerSuite) SetUpSuite(c *C) {
	idAllocator := testidentity.NewMockIdentityAllocator(nil)
	s.repo = policy.NewPolicyRepository(idAllocator, nil, nil, nil)
}

func (s *EndpointManagerSuite) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s *EndpointManagerSuite) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, wg *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	return 0, nil, nil, nil
}

func (s *EndpointManagerSuite) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

func (s *EndpointManagerSuite) UpdateNetworkPolicy(e regeneration.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy,
	proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	return nil, nil
}

func (s *EndpointManagerSuite) RemoveNetworkPolicy(e regeneration.EndpointInfoSource) {}

func (s *EndpointManagerSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *EndpointManagerSuite) GetCompilationLock() *lock.RWMutex {
	return nil
}

func (s *EndpointManagerSuite) GetCIDRPrefixLengths() (s6, s4 []int) {
	return nil, nil
}

func (s *EndpointManagerSuite) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

func (s *EndpointManagerSuite) Datapath() datapath.Datapath {
	return nil
}

func (s *EndpointManagerSuite) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *EndpointManagerSuite) RemoveRestoredDNSRules(epID uint16) {
}

type DummyRuleCacheOwner struct{}

func (d *DummyRuleCacheOwner) ClearPolicyConsumers(id uint16) *sync.WaitGroup {
	return &sync.WaitGroup{}
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func (s *EndpointManagerSuite) TestLookup(c *C) {
	type args struct {
		id string
	}
	type want struct {
		ep       bool
		err      error
		errCheck Checker
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
		cm        *apiv1.EndpointChangeRequest
	}{
		{
			name: "endpoint does not exist",
			setupArgs: func() args {
				return args{
					"1234",
				}
			},
			setupWant: func() want {
				return want{
					ep:       false,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by cilium local ID",
			cm: &apiv1.EndpointChangeRequest{
				ID: 1234,
			},
			setupArgs: func() args {
				return args{
					endpointid.NewCiliumID(1234),
				}
			},
			setupWant: func() want {
				return want{
					ep:       true,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by cilium global ID",
			cm: &apiv1.EndpointChangeRequest{
				ID: 1234,
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.CiliumGlobalIdPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					err:      ErrUnsupportedID,
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by container ID",
			cm: &apiv1.EndpointChangeRequest{
				ContainerID: "1234",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerIdPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       true,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by docker endpoint ID",
			cm: &apiv1.EndpointChangeRequest{
				DockerEndpointID: "1234",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.DockerEndpointPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       true,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by container name",
			cm: &apiv1.EndpointChangeRequest{
				ContainerName: "foo",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerNamePrefix, "foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       true,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by pod name",
			cm: &apiv1.EndpointChangeRequest{
				K8sNamespace: "default",
				K8sPodName:   "foo",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.PodNamePrefix, "default/foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       true,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
		{
			name: "endpoint by ipv4",
			cm: &apiv1.EndpointChangeRequest{
				Addressing: &apiv1.AddressPair{
					IPV4: "127.0.0.1",
				},
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.IPv4Prefix, "127.0.0.1"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       true,
					err:      nil,
					errCheck: Equals,
				}
			},
		},
		{
			name: "invalid ID",
			setupArgs: func() args {
				return args{
					endpointid.NewID("foo", "bar"),
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
		},
		{
			name: "invalid cilium ID",
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.CiliumLocalIdPrefix, "bar"),
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
		},
	}
	for _, tt := range tests {
		var ep *endpoint.Endpoint
		var err error
		mgr := New(&dummyEpSyncher{})
		if tt.cm != nil {
			ep, err = endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), tt.cm)
			c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
			err = mgr.expose(ep)
			c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		}

		args := tt.setupArgs()
		want := tt.setupWant()
		got, err := mgr.Lookup(args.id)
		c.Assert(err, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		if want.ep {
			c.Assert(got, checker.DeepEquals, ep, Commentf("Test Name: %s", tt.name))
		} else {
			c.Assert(got, IsNil, Commentf("Test Name: %s", tt.name))
		}
	}
}

func (s *EndpointManagerSuite) TestLookupCiliumID(c *C) {
	mgr := New(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 2, endpoint.StateReady)
	type args struct {
		id uint16
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "existing cilium ID",
			preTestRun: func() {
				ep.ID = 1
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				return args{
					1,
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.ID = 0
			},
		},
		{
			name: "non-existing cilium ID",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					1,
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupCiliumID(args.id)
		exists := mgr.EndpointExists(args.id)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		c.Assert(exists, checker.Equals, want.ep != nil, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupContainerID(c *C) {
	mgr := New(&dummyEpSyncher{})
	ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ContainerID: "foo",
	})
	c.Assert(err, IsNil)
	c.Assert(mgr.expose(ep), IsNil)

	good := mgr.LookupContainerID("foo")
	c.Assert(good, checker.DeepEquals, ep)

	bad := mgr.LookupContainerID("asdf")
	c.Assert(bad, IsNil)

}

func (s *EndpointManagerSuite) TestLookupIPv4(c *C) {
	mgr := New(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 4, endpoint.StateReady)
	type args struct {
		ip string
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "existing LookupIPv4",
			preTestRun: func() {
				ep.IPv4 = netip.MustParseAddr("127.0.0.1")
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				return args{
					"127.0.0.1",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.IPv4 = netip.Addr{}
			},
		},
		{
			name: "non-existing LookupIPv4",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"127.0.0.1",
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupIPv4(args.ip)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupPodName(c *C) {
	mgr := New(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 5, endpoint.StateReady)
	type args struct {
		podName string
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "existing PodName",
			preTestRun: func() {
				ep.K8sNamespace = "default"
				ep.K8sPodName = "foo"
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.IPv4 = netip.Addr{}
			},
		},
		{
			name: "non-existing PodName",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupPodName(args.podName)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestUpdateReferences(c *C) {
	var ep *endpoint.Endpoint
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name      string
		cm        apiv1.EndpointChangeRequest
		setupWant func() want
	}{
		{
			name: "Updating all references",
			cm: apiv1.EndpointChangeRequest{
				K8sNamespace:     "default",
				K8sPodName:       "foo",
				ContainerID:      "container",
				DockerEndpointID: "dockerendpointID",
				Addressing: &apiv1.AddressPair{
					IPV4: "127.0.0.1",
				},
				ContainerName: "containername",
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
		},
	}
	for _, tt := range tests {
		var err error
		ep, err = endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &tt.cm)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		mgr := New(&dummyEpSyncher{})

		err = mgr.expose(ep)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		want := tt.setupWant()
		mgr.updateReferencesLocked(ep, ep.IdentifiersLocked())

		ep = mgr.LookupContainerID(want.ep.GetContainerID())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerEndpoint(want.ep.GetDockerEndpointID())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupIPv4(want.ep.IPv4.String())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerContainerName(want.ep.GetContainerName())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupPodName(want.ep.GetK8sNamespaceAndPodName())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
	}
}

func (s *EndpointManagerSuite) TestRemove(c *C) {
	mgr := New(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 7, endpoint.StateReady)
	type args struct {
	}
	type want struct {
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Updating all references",
			preTestRun: func() {
				ep.ID = 1
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				return args{}
			},
			setupWant: func() want {
				return want{}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()

		mgr.RemoveAll(c)
		c.Assert(len(mgr.endpoints), Equals, 0, Commentf("Test Name: %s", tt.name))
		c.Assert(len(mgr.endpointsAux), Equals, 0, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestHasGlobalCT(c *C) {
	mgr := New(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
	type want struct {
		result bool
	}
	tests := []struct {
		name        string
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Endpoint with Conntrack global",
			preTestRun: func() {
				ep.ID = 1
				ep.Options = option.NewIntOptions(&endpoint.EndpointMutableOptionLibrary)
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupWant: func() want {
				return want{
					result: true,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
				ep.ID = 0
				ep.Options = nil
			},
		},
		{
			name: "Endpoint with Conntrack local",
			preTestRun: func() {
				ep.ID = 1
				ep.Options = option.NewIntOptions(&endpoint.EndpointMutableOptionLibrary)
				ep.Options.SetIfUnset(option.ConntrackLocal, option.OptionEnabled)
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupWant: func() want {
				return want{
					result: false,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
				ep.ID = 0
				ep.Options = nil
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		want := tt.setupWant()
		got := mgr.HasGlobalCT()
		c.Assert(got, checker.DeepEquals, want.result, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestWaitForEndpointsAtPolicyRev(c *C) {
	mgr := New(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
	type args struct {
		ctx    context.Context
		rev    uint64
		cancel context.CancelFunc
	}
	type want struct {
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Endpoint with revision already set",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(5)
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				return args{
					ctx: context.Background(),
					rev: 5,
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
			},
		},
		{
			name: "Context already timed out",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(5)
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				ctx, cancel := context.WithTimeout(context.Background(), 0)
				return args{
					ctx:    ctx,
					rev:    5,
					cancel: cancel,
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
			},
		},
		{
			name: "Revision is will never be set to the waiting revision",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(4)
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				return args{
					ctx:    ctx,
					rev:    5,
					cancel: cancel,
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.WaitForEndpointsAtPolicyRev(args.ctx, args.rev)
		c.Assert(got, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		if args.cancel != nil {
			args.cancel()
		}
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestMissingNodeLabelsUpdate(c *C) {
	node.SetTestLocalNodeStore()
	defer node.UnsetTestLocalNodeStore()
	// Initialize label filter config.
	labelsfilter.ParseLabelPrefixCfg(nil, "")
	mgr := New(&dummyEpSyncher{})
	hostEPID := uint16(17)
	hostEP := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
	hostEP.SetIsHost(true)
	hostEP.ID = hostEPID

	// Helper function to create test node object.
	newTestNode := func(labels map[string]string) *slim_corev1.Node {
		return &slim_corev1.Node{
			ObjectMeta: slim_metav1.ObjectMeta{
				Labels: labels,
			},
		}
	}

	// Validate that labels for host endpoint are correctly set.
	validateHostEPLabels := func(wantLabels map[string]string) {
		currHostIP, ok := mgr.endpoints[hostEPID]
		c.Assert(ok, Equals, true)
		c.Assert(currHostIP.OpLabels.IdentityLabels().K8sStringMap(), checker.DeepEquals, wantLabels)
	}

	oldNode := newTestNode(make(map[string]string))
	newNode := newTestNode(map[string]string{"k1": "v1"})

	// Host endpoint is not created in endpoint manager so the node update
	// is not consumed by endpoint manager.
	c.Assert(mgr.OnUpdateNode(oldNode, newNode, lock.NewStoppableWaitGroup()), IsNil)
	_, ok := mgr.endpoints[hostEPID]
	c.Assert(ok, Equals, false)

	// Now expose host endpoint.
	mgr.expose(hostEP)

	// Even though endpoint manager does not have k1=v1, the request is still accepted.
	oldNode = newTestNode(map[string]string{"k1": "v1"})
	newNode = newTestNode(map[string]string{"k2": "v2"})
	c.Assert(mgr.OnUpdateNode(oldNode, newNode, lock.NewStoppableWaitGroup()), IsNil)
	validateHostEPLabels(map[string]string{"k2": "v2"})

	// k3=v3 is not present in the endpoint manager so an error is not returned.
	oldNode = newTestNode(map[string]string{"k3": "v3"})
	newNode = newTestNode(map[string]string{"k4": "v4"})
	c.Assert(mgr.OnUpdateNode(oldNode, newNode, lock.NewStoppableWaitGroup()), NotNil)
}
