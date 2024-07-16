// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/cilium/cilium/api/v1/models"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

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

func setupEndpointManagerSuite(tb testing.TB) *EndpointManagerSuite {
	s := &EndpointManagerSuite{}
	s.repo = policy.NewPolicyRepository(nil, nil, nil, nil)

	return s
}

func (s *EndpointManagerSuite) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s *EndpointManagerSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *EndpointManagerSuite) GetCompilationLock() datapath.CompilationLock {
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

func (s *EndpointManagerSuite) RemoveRestoredDNSRules(epID uint16) {}

func (s *EndpointManagerSuite) AddIdentity(id *identity.Identity)                   {}
func (s *EndpointManagerSuite) RemoveIdentity(id *identity.Identity)                {}
func (s *EndpointManagerSuite) RemoveOldAddNewIdentity(old, new *identity.Identity) {}

type DummyRuleCacheOwner struct{}

func (d *DummyRuleCacheOwner) ClearPolicyConsumers(id uint16) *sync.WaitGroup {
	return &sync.WaitGroup{}
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, hr cell.Health) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func TestLookup(t *testing.T) {
	s := setupEndpointManagerSuite(t)

	type args struct {
		id string
	}
	type want struct {
		ep       bool
		err      error
		errCheck assert.ComparisonAssertionFunc
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues}
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.EqualValues,
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
					errCheck: assert.NotEqualValues,
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
					errCheck: assert.NotEqualValues,
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
					errCheck: assert.EqualValues,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ep *endpoint.Endpoint
			var err error
			mgr := New(&dummyEpSyncher{}, nil, nil)
			if tt.cm != nil {
				ep, err = endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), tt.cm)
				require.NoErrorf(t, err, "Test Name: %s", tt.name)
				err = mgr.expose(ep)
				require.NoErrorf(t, err, "Test Name: %s", tt.name)
			}

			args := tt.setupArgs()
			want := tt.setupWant()
			got, err := mgr.Lookup(args.id)
			want.errCheck(t, want.err, err, "Test Name: %s", tt.name)
			if want.ep {
				require.EqualValuesf(t, ep, got, "Test Name: %s", tt.name)
			} else {
				require.Nilf(t, got, "Test Name: %s", tt.name)
			}
		})
	}
}

func TestLookupCiliumID(t *testing.T) {
	s := setupEndpointManagerSuite(t)

	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 2, endpoint.StateReady)
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
				require.Nil(t, mgr.expose(ep))
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
		require.EqualValuesf(t, want.ep, got, "Test Name: %s", tt.name)
		require.Equal(t, want.ep != nil, exists, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}

func TestLookupCNIAttachmentID(t *testing.T) {
	s := setupEndpointManagerSuite(t)

	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), &apiv1.EndpointChangeRequest{
		ContainerID:            "foo",
		ContainerInterfaceName: "bar",
	})
	require.Nil(t, err)
	require.Nil(t, mgr.expose(ep))

	good := mgr.LookupCNIAttachmentID("foo:bar")
	require.EqualValues(t, ep, good)

	bad := mgr.LookupCNIAttachmentID("foo")
	require.Nil(t, bad)

	bad = mgr.LookupCNIAttachmentID("asdf")
	require.Nil(t, bad)
}

func TestLookupIPv4(t *testing.T) {
	s := setupEndpointManagerSuite(t)

	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 4, endpoint.StateReady)
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
				require.Nil(t, mgr.expose(ep))
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
		require.EqualValuesf(t, want.ep, got, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}

func TestLookupCEPName(t *testing.T) {
	s := setupEndpointManagerSuite(t)
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
				require.Nil(t, mgr.expose(ep))
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
				require.Nil(t, mgr.expose(ep))
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
		require.NoErrorf(t, err, "Test Name: %s", tt.name)
		tt.preTestRun(ep)
		args := tt.setupArgs()
		want := tt.setupWant(ep)
		got := mgr.LookupCEPName(args.podName)
		require.EqualValues(t, want.ep, got, "Test Name: %s", tt.name)
		tt.postTestRun(ep)
	}
}

func TestUpdateReferences(t *testing.T) {
	s := setupEndpointManagerSuite(t)
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
		require.NoErrorf(t, err, "Test Name: %s", tt.name)
		mgr := New(&dummyEpSyncher{}, nil, nil)

		err = mgr.expose(ep)
		require.NoErrorf(t, err, "Test Name: %s", tt.name)
		want := tt.setupWant()
		mgr.updateReferencesLocked(ep, ep.Identifiers())

		ep = mgr.LookupCNIAttachmentID(want.ep.GetCNIAttachmentID())
		require.EqualValues(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.lookupDockerEndpoint(want.ep.GetDockerEndpointID())
		require.EqualValues(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.LookupIPv4(want.ep.IPv4.String())
		require.EqualValues(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.lookupDockerContainerName(want.ep.GetContainerName())
		require.EqualValues(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.LookupCEPName(want.ep.GetK8sNamespaceAndCEPName())
		require.EqualValues(t, want.ep, ep, "Test Name: %s", tt.name)

		eps := mgr.GetEndpointsByPodName(want.ep.GetK8sNamespaceAndPodName())
		require.Len(t, eps, 1)
		require.EqualValues(t, want.ep, eps[0], "Test Name: %s", tt.name)
	}
}

func TestRemove(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 7, endpoint.StateReady)
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
				require.Nil(t, mgr.expose(ep))
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

		mgr.RemoveAll(t)
		require.Equal(t, 0, len(mgr.endpoints), "Test Name: %s", tt.name)
		require.Equal(t, 0, len(mgr.endpointsAux), "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}

func TestHasGlobalCT(t *testing.T) {
	s := setupEndpointManagerSuite(t)

	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
				require.Nil(t, mgr.expose(ep))
			},
			setupWant: func() want {
				return want{
					result: true,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
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
				require.Nil(t, mgr.expose(ep))
			},
			setupWant: func() want {
				return want{
					result: false,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
				ep.ID = 0
				ep.Options = nil
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		want := tt.setupWant()
		got := mgr.HasGlobalCT()
		require.EqualValues(t, want.result, got, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}

func TestWaitForEndpointsAtPolicyRev(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	mgr := New(&dummyEpSyncher{}, nil, nil)
	ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
	type args struct {
		ctx    context.Context
		rev    uint64
		cancel context.CancelFunc
	}
	type want struct {
		err      error
		errCheck assert.ComparisonAssertionFunc
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
				require.Nil(t, mgr.expose(ep))
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
					errCheck: assert.EqualValues,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
			},
		},
		{
			name: "Context already timed out",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(5)
				require.Nil(t, mgr.expose(ep))
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
					errCheck: assert.NotEqualValues,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
			},
		},
		{
			name: "Revision is will never be set to the waiting revision",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(4)
				require.Nil(t, mgr.expose(ep))
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
					errCheck: assert.NotEqualValues,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.WaitForEndpointsAtPolicyRev(args.ctx, args.rev)
		want.errCheck(t, want.err, got, "Test Name: %s", tt.name)
		if args.cancel != nil {
			args.cancel()
		}
		tt.postTestRun()
	}
}

func TestMissingNodeLabelsUpdate(t *testing.T) {
	// Initialize label filter config.
	labelsfilter.ParseLabelPrefixCfg(nil, nil, "")
	s := setupEndpointManagerSuite(t)
	mgr := New(&dummyEpSyncher{}, nil, nil)
	hostEPID := uint16(17)

	// Initialize the local node watcher before the host endpoint is created.
	// These labels are not propagated to the endpoint manager.
	mgr.localNodeStore = node.NewTestLocalNodeStore(node.LocalNode{Node: types.Node{}})
	mgr.startNodeLabelsObserver(nil)
	mgr.localNodeStore.Update(func(ln *node.LocalNode) { ln.Labels = map[string]string{"k1": "v1"} })
	_, ok := mgr.endpoints[hostEPID]
	require.EqualValues(t, ok, false)

	// Create host endpoint and expose it in the endpoint manager.
	ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
	ep.SetIsHost(true)
	ep.ID = hostEPID
	require.Nil(t, mgr.expose(ep))

	// Update node labels and verify that the node labels are updated correctly even if the old
	// labels {k1=v1} are not present in the endpoint manager's state.
	mgr.localNodeStore.Update(func(ln *node.LocalNode) { ln.Labels = map[string]string{"k2": "v2"} })
	hostEP, ok := mgr.endpoints[hostEPID]
	require.EqualValues(t, ok, true)
	got := hostEP.OpLabels.IdentityLabels().K8sStringMap()
	require.EqualValues(t, map[string]string{"k2": "v2"}, got)
}

func TestUpdateHostEndpointLabels(t *testing.T) {
	// Initialize label filter config.
	labelsfilter.ParseLabelPrefixCfg([]string{"k8s:!ignore1", "k8s:!ignore2"}, nil, "")
	s := setupEndpointManagerSuite(t)
	mgr := New(&dummyEpSyncher{}, nil, nil)
	hostEPID := uint16(17)
	type args struct {
		oldLabels, newLabels map[string]string
	}
	type want struct {
		labels      map[string]string
		labelsCheck assert.ComparisonAssertionFunc
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Add labels",
			preTestRun: func() {
				ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
				ep.SetIsHost(true)
				ep.ID = hostEPID
				require.Nil(t, mgr.expose(ep))
			},
			setupArgs: func() args {
				return args{
					newLabels: map[string]string{"k1": "v1"},
				}
			},
			setupWant: func() want {
				return want{
					labels:      map[string]string{"k1": "v1"},
					labelsCheck: assert.EqualValues,
				}
			},
			postTestRun: func() {
				if hostEP, ok := mgr.endpoints[hostEPID]; ok {
					mgr.WaitEndpointRemoved(hostEP)
				}
			},
		},
		{
			name: "Update labels",
			preTestRun: func() {
				ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
				ep.SetIsHost(true)
				ep.ID = hostEPID
				ep.OpLabels.Custom = labels.Labels{"k1": labels.NewLabel("k1", "v1", labels.LabelSourceK8s)}
				require.Nil(t, mgr.expose(ep))
			},
			setupArgs: func() args {
				return args{
					oldLabels: map[string]string{"k1": "v1"},
					newLabels: map[string]string{"k2": "v2"},
				}
			},
			setupWant: func() want {
				return want{
					labels:      map[string]string{"k2": "v2"},
					labelsCheck: assert.EqualValues,
				}
			},
			postTestRun: func() {
				if hostEP, ok := mgr.endpoints[hostEPID]; ok {
					mgr.WaitEndpointRemoved(hostEP)
				}
			},
		},
		{
			name: "Ignore labels",
			preTestRun: func() {
				ep := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
				ep.SetIsHost(true)
				ep.ID = hostEPID
				ep.OpLabels.Custom = labels.Labels{"k1": labels.NewLabel("k1", "v1", labels.LabelSourceK8s)}
				require.Nil(t, mgr.expose(ep))
			},
			setupArgs: func() args {
				return args{
					oldLabels: map[string]string{"k1": "v1"},
					newLabels: map[string]string{"k1": "v1", "ignore1": "v2", "ignore2": "v2"},
				}
			},
			setupWant: func() want {
				return want{
					labels:      map[string]string{"k1": "v1"},
					labelsCheck: assert.EqualValues,
				}
			},
			postTestRun: func() {
				if hostEP, ok := mgr.endpoints[hostEPID]; ok {
					mgr.WaitEndpointRemoved(hostEP)
				}
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		mgr.localNodeStore = node.NewTestLocalNodeStore(node.LocalNode{Node: types.Node{
			Labels: args.oldLabels,
		}})
		mgr.startNodeLabelsObserver(args.oldLabels)
		mgr.localNodeStore.Update(func(ln *node.LocalNode) { ln.Labels = args.newLabels })

		hostEP, ok := mgr.endpoints[hostEPID]
		require.EqualValues(t, ok, true)
		got := hostEP.OpLabels.IdentityLabels().K8sStringMap()
		want.labelsCheck(t, want.labels, got, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}
