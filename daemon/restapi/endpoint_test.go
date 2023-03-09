// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	identitymock "github.com/cilium/cilium/pkg/testutils/identity"
)

type endpointTestContext struct {
	endpoints        *fakeEndpoints
	endpointModifier *fakeEndpointModifier
	client           *client.Client
}

type endpointTestCase struct {
	name string
	test func(t *testing.T, ctx endpointTestContext)
}

var endpointTestCases = []endpointTestCase{
	{"ListEndpoints", testListEndpoints},
	{"GetEndpointID", testGetEndpointID},
	{"GetEndpointIDConfig", testGetEndpointIDConfig},
	{"GetEndpointIDLabels", testGetEndpointIDLabels},
	{"GetEndpointIDLog", testGetEndpointIDLog},
	{"GetEndpointIDHealthz", testGetEndpointIDHealthz},
	{"PutEndpointID", testPutEndpointID},
	{"PatchEndpointID", testPatchEndpointID},
	{"PatchEndpointIDLabels", testPatchEndpointIDLabels},
}

func TestEndpointHandlers(t *testing.T) {
	err := labelsfilter.ParseLabelPrefixCfg(nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}

	// The test context is populated by an invoke function.
	var ctx endpointTestContext

	h := hive.New(
		rateLimiterCell, // *api.APILimiterSet
		cell.Provide(
			func() *testing.T { return t },
			func() cache.IdentityAllocator {
				return identitymock.NewMockIdentityAllocator(nil)
			},
			newFakeEndpoints,        // endpointLookup
			newFakeEndpointModifier, // Promise[EndpointModifier]
		),

		// Provide the handlers for /endpoint and pull in the server cell,
		// which provides server.TestServer for testing.
		cell.Provide(newEndpointHandlers),

		server.SpecCell,
		server.Cell,

		// Provide the client against the test server.
		cell.Provide(
			func(s server.TestServer) (*client.Client, error) {
				return client.NewClient(s.URL)
			},
		),

		// Extract the fake endpoints and the API client
		cell.Invoke(func(client *client.Client, endpoints *fakeEndpoints, fem *fakeEndpointModifier) {
			ctx = endpointTestContext{
				endpoints:        endpoints,
				endpointModifier: fem,
				client:           client,
			}
		}),
	)

	if assert.NoError(t, h.Start(context.TODO())) {
		for _, testCase := range endpointTestCases {
			t.Run(testCase.name, func(t *testing.T) {
				testCase.test(t, ctx)
			})
		}

		assert.NoError(t, h.Stop(context.TODO()))
	}
}

var (
	testEndpointIDs = []uint16{123, 234}

	testEndpointOrchLabels = map[uint16]string{
		123: "foo=bar",
		234: "baz=quux",
	}

	testEndpointUserLabel = "custom=test"
)

func newFakeEndpoints(ia cache.IdentityAllocator) (*fakeEndpoints, endpointLookup) {
	newEndpointForTest := func(numID uint16, lbls string) *endpoint.Endpoint {
		ep := endpoint.NewEndpointWithState(nil, fakePolicyGetter{}, nil, nil, ia, numID, endpoint.StateReady)
		ep.OpLabels.OrchestrationIdentity = labels.NewLabelsFromSortedList(lbls)
		ep.OpLabels.Custom = labels.NewLabelsFromSortedList(testEndpointUserLabel)
		ep.Options.SetValidated(
			option.DebugPolicy,
			option.OptionEnabled,
		)
		ep.LogStatusOK(endpoint.BPF, "hello")
		return ep
	}

	endpoints := map[string]*endpoint.Endpoint{}
	for numID, lbl := range testEndpointOrchLabels {
		ep := newEndpointForTest(numID, lbl)
		defer ep.Stop()
		id := endpointid.NewCiliumID(int64(numID))
		endpoints[id] = ep
	}

	f := &fakeEndpoints{endpoints}
	return f, f
}

func testListEndpoints(t *testing.T, ctx endpointTestContext) {
	endpoints, err := ctx.client.EndpointList()
	assert.Nil(t, err)
	assert.NotNil(t, endpoints)
	assert.Len(t, endpoints, 2)

	for _, ep := range endpoints {
		assert.Contains(t, testEndpointIDs, uint16(ep.ID))
	}
}

// clientResponseStatus unfolds the error to find an implementation for ClientResponseStatus,
// which all the normal error responses implement.
func clientResponseStatus(t *testing.T, err error) (runtime.ClientResponseStatus, bool) {
	orig := err
	for err != nil {
		s, ok := err.(runtime.ClientResponseStatus)
		if ok {
			return s, true
		}
		fmt.Printf("%T did not implement ClientResponseStatus (%s)\n", err, err)
		err = errors.Unwrap(err)
	}
	assert.Fail(t, "ClientResponseStatus not implemented by error", orig)
	return nil, false
}

func testGetEndpointID(t *testing.T, ctx endpointTestContext) {
	t.Run("404", func(t *testing.T) {
		ok, err := ctx.client.EndpointGet("non-existing")
		assert.Nil(t, ok)
		if s, ok := clientResponseStatus(t, err); ok {
			assert.True(t, s.IsCode(404))
		}
	})
	t.Run("200", func(t *testing.T) {
		for _, epNumID := range testEndpointIDs {
			epID := endpointid.NewCiliumID(int64(epNumID))
			ok, err := ctx.client.EndpointGet(epID)
			assert.NoError(t, err)
			if assert.NotNil(t, ok) {
				assert.EqualValues(t, epNumID, ok.ID)
			}
			// TODO what else to assert?
			// Do we want golden tests here instead of manually asserting every field?
		}
	})
}

func testGetEndpointIDConfig(t *testing.T, ctx endpointTestContext) {
	t.Run("404", func(t *testing.T) {
		ok, err := ctx.client.EndpointGet("non-existing")
		assert.Nil(t, ok)
		if s, ok := clientResponseStatus(t, err); ok {
			assert.True(t, s.IsCode(404))
		}
	})
	t.Run("200", func(t *testing.T) {
		for _, epNumID := range testEndpointIDs {
			epID := endpointid.NewCiliumID(int64(epNumID))
			conf, err := ctx.client.EndpointConfigGet(epID)
			assert.Nil(t, err)
			if assert.NotNil(t, conf) {
				// TODO what to assert here
				actual := conf.Realized.LabelConfiguration.User
				expected := []string{"unspec:" + testEndpointUserLabel}
				assert.EqualValues(t, expected, actual)
			}
		}
	})
}

func testGetEndpointIDLabels(t *testing.T, ctx endpointTestContext) {
	t.Run("404", func(t *testing.T) {
		ok, err := ctx.client.EndpointLabelsGet("non-existing")
		assert.Nil(t, ok)
		assert.Error(t, err)
		// Due to use of client.Hint() in EndpointLabelsGet() we don't have
		// the original error to type-match on. Revisit use of Hint()?
		assert.Contains(t, err.Error(), "getEndpointIdLabelsNotFound")
	})

	t.Run("200", func(t *testing.T) {
		for _, epNumID := range testEndpointIDs {
			epID := endpointid.NewCiliumID(int64(epNumID))
			labelConf, err := ctx.client.EndpointLabelsGet(epID)
			assert.NoError(t, err)
			if assert.NotNil(t, labelConf) {
				actual := labelConf.Status.Realized.User
				expected := []string{"unspec:" + testEndpointUserLabel}
				assert.EqualValues(t, expected, actual)
			}
		}
	})
}

func testGetEndpointIDLog(t *testing.T, ctx endpointTestContext) {
	t.Run("404", func(t *testing.T) {
		ok, err := ctx.client.EndpointLogGet("non-existing")
		assert.Nil(t, ok)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "getEndpointIdLogNotFound")
	})

	t.Run("200", func(t *testing.T) {
		for _, epNumID := range testEndpointIDs {
			epID := endpointid.NewCiliumID(int64(epNumID))
			log, err := ctx.client.EndpointLogGet(epID)
			assert.NoError(t, err)
			if assert.Len(t, log, 1) {
				assert.Equal(t, "hello", log[0].Message)
			}
		}
	})
}

func testGetEndpointIDHealthz(t *testing.T, ctx endpointTestContext) {
	t.Run("404", func(t *testing.T) {
		ok, err := ctx.client.EndpointHealthGet("non-existing")
		assert.Nil(t, ok)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "getEndpointIdHealthzNotFound")
	})

	t.Run("200", func(t *testing.T) {
		for _, epNumID := range testEndpointIDs {
			epID := endpointid.NewCiliumID(int64(epNumID))
			health, err := ctx.client.EndpointHealthGet(epID)
			assert.NoError(t, err)
			assert.EqualValues(t, "OK", health.Bpf)
		}
	})
}

func testPutEndpointID(t *testing.T, ctx endpointTestContext) {
	t.Run("200", func(t *testing.T) {
		contID := "test-container-id"
		ep := &models.EndpointChangeRequest{
			ContainerID:           contID,
			Labels:                []string{"test=true"},
			State:                 models.EndpointStateWaitingDashForDashIdentity.Pointer(),
			Addressing:            &models.AddressPair{},
			K8sPodName:            "pod-name",
			K8sNamespace:          "pod-namespace",
			DatapathConfiguration: &models.EndpointDatapathConfiguration{},
		}
		err := ctx.client.EndpointCreate(ep)
		if assert.NoError(t, err) {
			assert.Equal(t, contID, ctx.endpointModifier.lastCreate.ContainerID)
			assert.Equal(t, "pod-name", ctx.endpointModifier.lastCreate.K8sPodName)
			assert.EqualValues(t, []string{"test=true"}, ctx.endpointModifier.lastCreate.Labels)
		}
	})
}

func testPatchEndpointID(t *testing.T, ctx endpointTestContext) {
	t.Run("200", func(t *testing.T) {
		epNumID := testEndpointIDs[0]
		epID := endpointid.NewCiliumID(int64(epNumID))
		contID := "test-container-id"
		p := &models.EndpointChangeRequest{
			ContainerID: contID,
			State:       models.EndpointStateReady.Pointer(),
		}
		err := ctx.client.EndpointPatch(epID, p)

		if assert.NoError(t, err) {
			assert.Equal(t, contID, ctx.endpointModifier.lastPatch.ContainerID)
		}
	})
}

func testPatchEndpointIDLabels(t *testing.T, ctx endpointTestContext) {
	epNumID := testEndpointIDs[0]
	epID := endpointid.NewCiliumID(int64(epNumID))
	t.Run("200", func(t *testing.T) {
		err := ctx.client.EndpointLabelsPatch(epID, []string{"user-label=test"}, nil)
		ep := ctx.endpoints.eps[epID]
		if assert.NoError(t, err) {
			assert.Equal(t,
				ep.OpLabels.Custom.String(),
				"unspec:custom=test,unspec:user-label=test",
			)
			// Revert the modification.
			err = ctx.client.EndpointLabelsPatch(epID, nil, []string{"user-label=test"})
			if assert.NoError(t, err) {
				assert.Equal(t,
					ep.OpLabels.Custom.String(),
					"unspec:custom=test",
				)
			}
		}
	})

	t.Run("reserved:world", func(t *testing.T) {
		// Use of reserved:world as user label not allowed.
		err := ctx.client.EndpointLabelsPatch(epID, []string{"reserved:world"}, nil)
		assert.Error(t, err, "adding reserved:world label results in error")
		assert.Contains(t, err.Error(), "Not allowed to add reserved labels")
	})
}

//
// Fakes
//

type fakeEndpoints struct {
	eps map[string]*endpoint.Endpoint
}

func (f *fakeEndpoints) GetEndpoints() []*endpoint.Endpoint           { return maps.Values(f.eps) }
func (f *fakeEndpoints) Lookup(id string) (*endpoint.Endpoint, error) { return f.eps[id], nil }
func (f *fakeEndpoints) UpdateReferences(ep *endpoint.Endpoint) error { return nil }

var _ endpointLookup = &fakeEndpoints{}

type fakeEndpointModifier struct {
	lastCreate *models.EndpointChangeRequest
	lastDelete *string
	lastPatch  *models.EndpointChangeRequest
}

func (f *fakeEndpointModifier) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (int, error) {
	f.lastCreate = epTemplate
	return 0, nil
}

func (f *fakeEndpointModifier) DeleteEndpoint(id string) (int, error) {
	f.lastDelete = &id
	return 0, nil
}

func (f *fakeEndpointModifier) PatchEndpoint(ctx context.Context, ID string, epTemplate *models.EndpointChangeRequest) (int, error) {
	f.lastPatch = epTemplate
	return 0, nil
}

func newFakeEndpointModifier() (*fakeEndpointModifier, promise.Promise[EndpointModifier]) {
	fem := &fakeEndpointModifier{}
	return fem, promise.Resolved(EndpointModifier(fem))
}

var _ EndpointModifier = &fakeEndpointModifier{}

type fakePolicyGetter struct{}

func (fakePolicyGetter) GetPolicyRepository() *policy.Repository {
	return policy.NewPolicyRepository(nil, nil, nil, nil)
}
