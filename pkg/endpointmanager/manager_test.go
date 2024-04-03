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
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
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

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, hr cell.HealthReporter) {
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
			name: "endpoint by CNI attachment ID",
			cm: &apiv1.EndpointChangeRequest{
				ContainerID:            "1234",
				ContainerInterfaceName: "eth0",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewCNIAttachmentID("1234", "eth0"),
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
			name: "endpoint by CNI attachment ID without interface",
			cm: &apiv1.EndpointChangeRequest{
				ContainerID: "1234",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewCNIAttachmentID("1234", ""),
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
			name: "endpoint by container ID (deprecated)",
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
			name: "endpoint by container name (deprecated)",
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
			name: "endpoint by cep name",
			cm: &apiv1.EndpointChangeRequest{
				K8sNamespace: "default",
				K8sPodName:   "foo",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.CEPNamePrefix, "default/foo"),
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
			name: "endpoint by cep name with interface",
			cm: &apiv1.EndpointChangeRequest{
				K8sNamespace:           "default",
				K8sPodName:             "foo",
				ContainerInterfaceName: "net1",
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.CEPNamePrefix, "default/foo"),
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
			name: "endpoint by cep name with interface and disabled legacy identifers",
			cm: &apiv1.EndpointChangeRequest{
				K8sNamespace:             "default",
				K8sPodName:               "foo",
				ContainerInterfaceName:   "net1",
				DisableLegacyIdentifiers: true,
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.CEPNamePrefix, "default/foo-net1"),
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
		{
			name: "invalid lookup with container id with disabled legacy identifiers",
			cm: &apiv1.EndpointChangeRequest{
				ContainerID:              "1234",
				DisableLegacyIdentifiers: true,
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerIdPrefix, "1234"),
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
	}
	for _, tt := range tests {
		var ep *endpoint.Endpoint
		var err error
		mgr := New(&dummyEpSyncher{}, nil, nil)
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
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 2, endpoint.StateReady)
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

func (s *EndpointManagerSuite) TestLookupCNIAttachmentID(c *C) {
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ContainerID:            "foo",
		ContainerInterfaceName: "bar",
	})
	c.Assert(err, IsNil)
	c.Assert(mgr.expose(ep), IsNil)

	good := mgr.LookupCNIAttachmentID("foo:bar")
	c.Assert(good, checker.DeepEquals, ep)

	bad := mgr.LookupCNIAttachmentID("foo")
	c.Assert(bad, IsNil)

	bad = mgr.LookupCNIAttachmentID("asdf")
	c.Assert(bad, IsNil)
}

func (s *EndpointManagerSuite) TestLookupIPv4(c *C) {
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 4, endpoint.StateReady)
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

func (s *EndpointManagerSuite) TestLookupCEPName(c *C) {
	mgr := New(&dummyEpSyncher{}, nil, nil)
	type args struct {
		podName string
	}
	type want struct {
		ep *endpoint.Endpoint
	}
	tests := []struct {
		name        string
		cm          apiv1.EndpointChangeRequest
		setupArgs   func() args
		setupWant   func(*endpoint.Endpoint) want
		preTestRun  func(*endpoint.Endpoint)
		postTestRun func(*endpoint.Endpoint)
	}{
		{
			name: "existing pod name",
			cm: apiv1.EndpointChangeRequest{
				K8sNamespace: "default",
				K8sPodName:   "foo",
			},
			preTestRun: func(ep *endpoint.Endpoint) {
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func(ep *endpoint.Endpoint) want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func(ep *endpoint.Endpoint) {
				mgr.WaitEndpointRemoved(ep)
			},
		},
		{
			name: "existing pod name with container interface name",
			cm: apiv1.EndpointChangeRequest{
				K8sNamespace:             "default",
				K8sPodName:               "bar",
				ContainerInterfaceName:   "eth1",
				DisableLegacyIdentifiers: true,
			},
			preTestRun: func(ep *endpoint.Endpoint) {
				c.Assert(mgr.expose(ep), IsNil)
			},
			setupArgs: func() args {
				return args{
					"default/bar-eth1",
				}
			},
			setupWant: func(ep *endpoint.Endpoint) want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func(ep *endpoint.Endpoint) {
				mgr.WaitEndpointRemoved(ep)
			},
		},
		{
			name: "non-existing PodName",
			preTestRun: func(ep *endpoint.Endpoint) {
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func(ep *endpoint.Endpoint) want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func(ep *endpoint.Endpoint) {
			},
		},
	}
	for _, tt := range tests {
		ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &tt.cm)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		tt.preTestRun(ep)
		args := tt.setupArgs()
		want := tt.setupWant(ep)
		got := mgr.LookupCEPName(args.podName)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun(ep)
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
		mgr := New(&dummyEpSyncher{}, nil, nil)

		err = mgr.expose(ep)
		c.Assert(err, IsNil, Commentf("Test Name: %s", tt.name))
		want := tt.setupWant()
		mgr.updateReferencesLocked(ep, ep.Identifiers())

		ep = mgr.LookupCNIAttachmentID(want.ep.GetCNIAttachmentID())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerEndpoint(want.ep.GetDockerEndpointID())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupIPv4(want.ep.IPv4.String())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerContainerName(want.ep.GetContainerName())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupCEPName(want.ep.GetK8sNamespaceAndCEPName())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		eps := mgr.GetEndpointsByPodName(want.ep.GetK8sNamespaceAndPodName())
		c.Assert(eps, HasLen, 1)
		c.Assert(eps[0], checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
	}
}

func (s *EndpointManagerSuite) TestRemove(c *C) {
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 7, endpoint.StateReady)
	type args struct{}
	type want struct{}
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
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
				ep = endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
				ep = endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
				ep = endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
				ep = endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
				ep = endpoint.NewTestEndpointWithState(c, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
