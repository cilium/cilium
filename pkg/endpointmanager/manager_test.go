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
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
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
	repo policy.PolicyRepository
}

func setupEndpointManagerSuite(tb testing.TB) *EndpointManagerSuite {
	s := &EndpointManagerSuite{}
	s.repo = policy.NewPolicyRepository(hivetest.Logger(tb), nil, nil, nil, nil, api.NewPolicyMetricsNoop())

	return s
}

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
					errCheck: assert.EqualValues,
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
			logger := hivetest.Logger(t)
			mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
			if tt.cm != nil {
				ep, err = endpoint.NewEndpointFromChangeModel(context.Background(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, tt.cm)
				require.NoErrorf(t, err, "Test Name: %s", tt.name)
				err = mgr.expose(ep)
				require.NoErrorf(t, err, "Test Name: %s", tt.name)
			}

			args := tt.setupArgs()
			want := tt.setupWant()
			got, err := mgr.Lookup(args.id)
			want.errCheck(t, want.err, err, "Test Name: %s", tt.name)
			if want.ep {
				require.Equalf(t, ep, got, "Test Name: %s", tt.name)
			} else {
				require.Nilf(t, got, "Test Name: %s", tt.name)
			}
		})
	}
}

func TestLookupCiliumID(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)

	model := newTestEndpointModel(2, endpoint.StateReady)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

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
				require.NoError(t, mgr.expose(ep))
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
		require.Equalf(t, want.ep, got, "Test Name: %s", tt.name)
		require.Equal(t, want.ep != nil, exists, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}

func TestLookupCNIAttachmentID(t *testing.T) {
	s := setupEndpointManagerSuite(t)

	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, nil, nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, &apiv1.EndpointChangeRequest{
		ContainerID:            "foo",
		ContainerInterfaceName: "bar",
	})
	require.NoError(t, err)
	require.NoError(t, mgr.expose(ep))

	good := mgr.LookupCNIAttachmentID("foo:bar")
	require.Equal(t, ep, good)

	bad := mgr.LookupCNIAttachmentID("foo")
	require.Nil(t, bad)

	bad = mgr.LookupCNIAttachmentID("asdf")
	require.Nil(t, bad)
}

func TestLookupIPv4(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)

	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	model := newTestEndpointModel(4, endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

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
				require.NoError(t, mgr.expose(ep))
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
		require.Equalf(t, want.ep, got, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}

func TestLookupCEPName(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
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
				require.NoError(t, mgr.expose(ep))
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
				require.NoError(t, mgr.expose(ep))
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
		ep, err := endpoint.NewEndpointFromChangeModel(context.Background(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, nil, nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, &tt.cm)
		require.NoErrorf(t, err, "Test Name: %s", tt.name)
		tt.preTestRun(ep)
		args := tt.setupArgs()
		want := tt.setupWant(ep)
		got := mgr.LookupCEPName(args.podName)
		require.Equal(t, want.ep, got, "Test Name: %s", tt.name)
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
		ep, err = endpoint.NewEndpointFromChangeModel(context.Background(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, nil, nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, &tt.cm)
		require.NoErrorf(t, err, "Test Name: %s", tt.name)
		logger := hivetest.Logger(t)
		mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)

		err = mgr.expose(ep)
		require.NoErrorf(t, err, "Test Name: %s", tt.name)
		want := tt.setupWant()
		mgr.updateReferencesLocked(ep, ep.Identifiers())

		ep = mgr.LookupCNIAttachmentID(want.ep.GetCNIAttachmentID())
		require.Equal(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.lookupDockerEndpoint(want.ep.GetDockerEndpointID())
		require.Equal(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.LookupIPv4(want.ep.IPv4.String())
		require.Equal(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.lookupDockerContainerName(want.ep.GetContainerName())
		require.Equal(t, want.ep, ep, "Test Name: %s", tt.name)

		ep = mgr.LookupCEPName(want.ep.GetK8sNamespaceAndCEPName())
		require.Equal(t, want.ep, ep, "Test Name: %s", tt.name)

		eps := mgr.GetEndpointsByPodName(want.ep.GetK8sNamespaceAndPodName())
		require.Len(t, eps, 1)
		require.Equal(t, want.ep, eps[0], "Test Name: %s", tt.name)
	}
}

func TestRemove(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	model := newTestEndpointModel(7, endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

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
				require.NoError(t, mgr.expose(ep))
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
		require.Empty(t, mgr.endpoints, "Test Name: %s", tt.name)
		require.Empty(t, mgr.endpointsAux, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}

func TestWaitForEndpointsAtPolicyRev(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	model := newTestEndpointModel(1, endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)
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
				require.NoError(t, mgr.expose(ep))
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
				model := newTestEndpointModel(1, endpoint.StateReady)
				ep, err = endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
				require.NoError(t, err)

				ep.Start(uint16(model.ID))
				t.Cleanup(ep.Stop)
			},
		},
		{
			name: "Context already timed out",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(5)
				require.NoError(t, mgr.expose(ep))
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
				model := newTestEndpointModel(1, endpoint.StateReady)
				ep, err = endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
				require.NoError(t, err)

				ep.Start(uint16(model.ID))
				t.Cleanup(ep.Stop)
			},
		},
		{
			name: "Revision is will never be set to the waiting revision",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(4)
				require.NoError(t, mgr.expose(ep))
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
				model := newTestEndpointModel(1, endpoint.StateReady)
				ep, err = endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
				require.NoError(t, err)

				ep.Start(uint16(model.ID))
				t.Cleanup(ep.Stop)
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
	logger := hivetest.Logger(t)
	// Initialize label filter config.
	labelsfilter.ParseLabelPrefixCfg(logger, nil, nil, "")
	s := setupEndpointManagerSuite(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	hostEPID := uint16(17)

	// Initialize the local node watcher before the host endpoint is created.
	// These labels are not propagated to the endpoint manager.
	mgr.localNodeStore = node.NewTestLocalNodeStore(node.LocalNode{Node: types.Node{}})
	mgr.startNodeLabelsObserver(nil)
	mgr.localNodeStore.Update(func(ln *node.LocalNode) { ln.Labels = map[string]string{"k1": "v1"} })
	_, ok := mgr.endpoints[hostEPID]
	require.False(t, ok)

	// Create host endpoint and expose it in the endpoint manager.
	model := newTestEndpointModel(1, endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

	ep.SetIsHost(true)
	ep.ID = hostEPID
	require.NoError(t, mgr.expose(ep))

	// Update node labels and verify that the node labels are updated correctly even if the old
	// labels {k1=v1} are not present in the endpoint manager's state.
	mgr.localNodeStore.Update(func(ln *node.LocalNode) { ln.Labels = map[string]string{"k2": "v2"} })
	hostEP, ok := mgr.endpoints[hostEPID]
	require.True(t, ok)
	got := hostEP.GetOpLabels()
	require.Equal(t, []string{"k8s:k2=v2"}, got)
}

func TestUpdateHostEndpointLabels(t *testing.T) {
	logger := hivetest.Logger(t)
	// Initialize label filter config.
	labelsfilter.ParseLabelPrefixCfg(logger, []string{"k8s:!ignore1", "k8s:!ignore2"}, nil, "")
	s := setupEndpointManagerSuite(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
	hostEPID := uint16(17)
	type args struct {
		oldLabels, newLabels map[string]string
	}
	type want struct {
		labels      []string
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
				model := newTestEndpointModel(1, endpoint.StateReady)
				ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
				require.NoError(t, err)

				ep.Start(uint16(model.ID))
				t.Cleanup(ep.Stop)

				ep.SetIsHost(true)
				ep.ID = hostEPID
				require.NoError(t, mgr.expose(ep))
			},
			setupArgs: func() args {
				return args{
					newLabels: map[string]string{"k1": "v1"},
				}
			},
			setupWant: func() want {
				return want{
					labels:      []string{"k8s:k1=v1"},
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
				model := newTestEndpointModel(1, endpoint.StateReady)
				model.Labels = apiv1.Labels([]string{"k8s:k1=v1"})
				ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
				require.NoError(t, err)

				ep.Start(uint16(model.ID))
				t.Cleanup(ep.Stop)

				ep.SetIsHost(true)
				ep.ID = hostEPID
				require.NoError(t, mgr.expose(ep))
			},
			setupArgs: func() args {
				return args{
					oldLabels: map[string]string{"k1": "v1"},
					newLabels: map[string]string{"k2": "v2"},
				}
			},
			setupWant: func() want {
				return want{
					labels:      []string{"k8s:k2=v2"},
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
				model := newTestEndpointModel(1, endpoint.StateReady)
				model.Labels = apiv1.Labels([]string{"k8s:k1=v1"})
				ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
				ep.SetIsHost(true)
				require.NoError(t, err)

				ep.Start(uint16(model.ID))
				t.Cleanup(ep.Stop)

				ep.ID = hostEPID
				require.NoError(t, mgr.expose(ep))
			},
			setupArgs: func() args {
				return args{
					oldLabels: map[string]string{"k1": "v1"},
					newLabels: map[string]string{"k1": "v1", "ignore1": "v2", "ignore2": "v2"},
				}
			},
			setupWant: func() want {
				return want{
					labels:      []string{"k8s:k1=v1"},
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
		require.True(t, ok)
		got := hostEP.GetOpLabels()
		want.labelsCheck(t, want.labels, got, "Test Name: %s", tt.name)
		tt.postTestRun()
	}
}
