// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	QAIPv6Addr   = netip.MustParseAddr("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	QAIPv4Addr   = netip.MustParseAddr("10.11.12.13")
	ProdIPv6Addr = netip.MustParseAddr("cafe:cafe:cafe:cafe:aaaa:aaaa:1111:1112")
	ProdIPv4Addr = netip.MustParseAddr("10.11.12.14")

	lblProd = labels.ParseLabel("Prod")
	lblQA   = labels.ParseLabel("QA")
	lblFoo  = labels.ParseLabel("foo")
	lblBar  = labels.ParseLabel("bar")
	lblJoe  = labels.ParseLabel("user=joe")
	lblPete = labels.ParseLabel("user=pete")

	testQAEndpointID   = uint16(1)
	testProdEndpointID = uint16(2)

	regenerationMetadata = &regeneration.ExternalRegenerationMetadata{
		Reason:            "test",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
	}

	CNPAllowTCP80 = api.PortRule{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
	}
	CNPAllowGETbar = api.PortRule{
		Ports: CNPAllowTCP80.Ports,
		Rules: &api.L7Rules{
			HTTP: []api.PortRuleHTTP{
				{
					Path:   "/bar",
					Method: "GET",
				},
			},
		},
	}
	CNPAllowGETbarLog = api.PortRule{
		Ports: CNPAllowTCP80.Ports,
		Rules: &api.L7Rules{
			HTTP: []api.PortRuleHTTP{
				{
					Method: "GET",
					HeaderMatches: []*api.HeaderMatch{{
						Mismatch: api.MismatchActionLog,
						Name:     ":path",
						Value:    "/bar",
					}},
				},
			},
		},
	}

	PNPAllowAll = cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{},
			},
		},
	}

	PNPAllowGETbar = cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{
					Headers: []*envoy_config_route.HeaderMatcher{
						{
							Name: ":method",
							HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
								StringMatch: &envoy_type_matcher.StringMatcher{
									MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
										SafeRegex: &envoy_type_matcher.RegexMatcher{
											Regex: "GET",
										},
									},
								},
							},
						},
						{
							Name: ":path",
							HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
								StringMatch: &envoy_type_matcher.StringMatcher{
									MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
										SafeRegex: &envoy_type_matcher.RegexMatcher{
											Regex: "/bar",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	PNPAllowGETbarLog = cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{
					Headers: []*envoy_config_route.HeaderMatcher{
						{
							Name: ":method",
							HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
								StringMatch: &envoy_type_matcher.StringMatcher{
									MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
										SafeRegex: &envoy_type_matcher.RegexMatcher{
											Regex: "GET",
										},
									},
								},
							},
						},
					},
					HeaderMatches: []*cilium.HeaderMatch{
						{
							Name:           ":path",
							Value:          "/bar",
							MismatchAction: cilium.HeaderMatch_CONTINUE_ON_MISMATCH,
						},
					},
				},
			},
		},
	}

	PNPAllowWildcardGETbar = cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{},
				PNPAllowGETbar.HttpRules.HttpRules[0],
			},
		},
	}
)

// getXDSNetworkPolicies returns the representation of the xDS network policies
// as a map of IP addresses to NetworkPolicy objects
func (ds *DaemonSuite) getXDSNetworkPolicies(t *testing.T, resourceNames []string) map[string]*cilium.NetworkPolicy {
	networkPolicies, err := ds.envoyXdsServer.GetNetworkPolicies(resourceNames)
	require.NoError(t, err)
	return networkPolicies
}

func prepareEndpointDirs() (cleanup func(), err error) {
	var testDirs []string
	for testEndpointID := range []uint16{testQAEndpointID, testProdEndpointID} {
		testEPDir := fmt.Sprintf("%d", testEndpointID)
		if err = os.Mkdir(testEPDir, 0755); err != nil {
			for _, dir := range testDirs {
				os.RemoveAll(dir)
			}
			return func() {}, err
		}
		testDirs = append(testDirs, testEPDir)
	}
	return func() {
		for _, testEPDir := range testDirs {
			os.RemoveAll(filepath.Join(testEPDir, common.CHeaderFileName))
			os.RemoveAll(filepath.Join(testEPDir, common.EndpointStateFileName))
			time.Sleep(1 * time.Second)
			os.RemoveAll(testEPDir)
			os.RemoveAll(fmt.Sprintf("%s_backup", testEPDir))
		}
	}, nil
}

func (ds *DaemonSuite) prepareEndpoint(t *testing.T, identity *identity.Identity, qa bool) *endpoint.Endpoint {
	testEndpointID := testProdEndpointID
	if qa {
		testEndpointID = testQAEndpointID
	}
	model := &models.EndpointChangeRequest{
		ID:    int64(testEndpointID),
		State: ptr.To(models.EndpointState(endpoint.StateWaitingForIdentity)),
	}
	e, err := ds.d.endpointCreator.NewEndpointFromChangeModel(t.Context(), model)
	require.NoError(t, err)

	e.Start(testEndpointID)
	t.Cleanup(e.Stop)

	e.SetPropertyValue(endpoint.PropertyWithouteBPFDatapath, true)
	e.SetPropertyValue(endpoint.PropertySkipBPFPolicy, true)
	if qa {
		e.IPv6 = QAIPv6Addr
		e.IPv4 = QAIPv4Addr
	} else {
		e.IPv6 = ProdIPv6Addr
		e.IPv4 = ProdIPv4Addr
	}
	e.SetIdentity(identity, true)

	ready := e.SetState(endpoint.StateWaitingToRegenerate, "test")
	require.True(t, ready)
	buildSuccess := <-e.Regenerate(regenerationMetadata)
	require.True(t, buildSuccess)

	return e
}

func (ds *DaemonSuite) regenerateEndpoint(t *testing.T, e *endpoint.Endpoint) {
	ready := e.SetState(endpoint.StateWaitingToRegenerate, "test")
	require.True(t, ready)
	buildSuccess := <-e.Regenerate(regenerationMetadata)
	require.True(t, buildSuccess)
}

func TestUpdateConsumerMapEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testUpdateConsumerMap(t)
}

func (ds *DaemonSuite) testUpdateConsumerMap(t *testing.T) {
	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblJoe),
							api.NewESFromLabels(lblPete),
							api.NewESFromLabels(lblFoo),
						},
					},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblFoo),
						},
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblQA),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromRequires: []api.EndpointSelector{
							api.NewESFromLabels(lblQA),
						},
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblProd),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromRequires: []api.EndpointSelector{
							api.NewESFromLabels(lblProd),
						},
					},
				},
			},
		},
	}
	for i := range rules {
		rules[i].Sanitize()
	}

	ds.envoyXdsServer.RemoveAllNetworkPolicies()

	ds.policyImport(rules)

	// Prepare the identities necessary for testing
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx, false)
	prodBarLbls := labels.Labels{lblBar.Key: lblBar, lblProd.Key: lblProd}
	prodBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), prodBarLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), prodBarSecLblsCtx, false)
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooSecLblsCtx, false)
	prodFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd}
	prodFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), prodFooLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), prodFooSecLblsCtx, false)
	prodFooJoeLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd, lblJoe.Key: lblJoe}
	prodFooJoeSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), prodFooJoeLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), prodFooJoeSecLblsCtx, false)

	// Prepare endpoints
	cleanup, err2 := prepareEndpointDirs()
	require.NoError(t, err2)
	defer cleanup()

	eQABar := ds.prepareEndpoint(t, qaBarSecLblsCtx, true)
	require.False(t, eQABar.Allows(qaBarSecLblsCtx.ID))
	require.False(t, eQABar.Allows(prodBarSecLblsCtx.ID))
	require.True(t, eQABar.Allows(qaFooSecLblsCtx.ID))
	require.False(t, eQABar.Allows(prodFooSecLblsCtx.ID))

	eProdBar := ds.prepareEndpoint(t, prodBarSecLblsCtx, false)
	require.False(t, eProdBar.Allows(0))
	require.False(t, eProdBar.Allows(qaBarSecLblsCtx.ID))
	require.False(t, eProdBar.Allows(prodBarSecLblsCtx.ID))
	require.False(t, eProdBar.Allows(qaFooSecLblsCtx.ID))
	require.True(t, eProdBar.Allows(prodFooSecLblsCtx.ID))
	require.True(t, eProdBar.Allows(prodFooJoeSecLblsCtx.ID))

	// Check that both policies have been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(t, nil)
	require.Len(t, networkPolicies, 4)

	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	require.NotNil(t, qaBarNetworkPolicy)
	expectedRemotePolicies := []uint32{
		uint32(qaFooSecLblsCtx.ID),
		// The prodFoo* identities are allowed by FromEndpoints but rejected by
		// FromRequires, so they are not included in the remote policies:
		// uint32(prodFooSecLblsCtx.ID),
		// uint32(prodFooJoeSecLblsCtx.ID),
	}
	slices.Sort(expectedRemotePolicies)
	expectedNetworkPolicy := &cilium.NetworkPolicy{
		EndpointIps:      []string{QAIPv6Addr.String(), QAIPv4Addr.String()},
		EndpointId:       uint64(eQABar.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     0,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies,
					},
				},
			},
			{
				Port:     80,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies,
						L7:             &PNPAllowGETbar,
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_config_core.SocketAddress_TCP},
		},
	}

	require.EqualExportedValues(t, expectedNetworkPolicy, qaBarNetworkPolicy)

	prodBarNetworkPolicy := networkPolicies[ProdIPv4Addr.String()]
	require.NotNil(t, prodBarNetworkPolicy)
	expectedRemotePolicies = []uint32{
		// The qaFoo identity is allowed by FromEndpoints but rejected by
		// FromRequires, so it is not included in the remote policies:
		// uint64(qaFooSecLblsCtx.ID),
		uint32(prodFooSecLblsCtx.ID),
		uint32(prodFooJoeSecLblsCtx.ID),
	}
	slices.Sort(expectedRemotePolicies)

	expectedNetworkPolicy = &cilium.NetworkPolicy{
		EndpointIps:      []string{ProdIPv6Addr.String(), ProdIPv4Addr.String()},
		EndpointId:       uint64(eProdBar.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     0,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies,
					},
				},
			},
			{
				Port:     80,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies,
						L7:             &PNPAllowGETbar,
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_config_core.SocketAddress_TCP},
		},
	}
	require.EqualExportedValues(t, expectedNetworkPolicy, prodBarNetworkPolicy)
}

func TestL4L7ShadowingEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testL4L7Shadowing(t)
}

func (ds *DaemonSuite) testL4L7Shadowing(t *testing.T) {
	// Prepare the identities necessary for testing
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx, false)
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooSecLblsCtx, false)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{
						// Allow all on port 80 (no proxy)
						CNPAllowTCP80,
					},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblFoo),
						},
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbarLog,
					},
				},
			},
		},
	}
	for i := range rules {
		rules[i].Sanitize()
	}

	ds.envoyXdsServer.RemoveAllNetworkPolicies()

	ds.policyImport(rules)

	// Prepare endpoints
	cleanup, err := prepareEndpointDirs()
	require.NoError(t, err)
	defer cleanup()

	eQABar := ds.prepareEndpoint(t, qaBarSecLblsCtx, true)
	require.False(t, eQABar.Allows(qaBarSecLblsCtx.ID))
	require.False(t, eQABar.Allows(qaFooSecLblsCtx.ID))

	// Check that both policies have been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(t, nil)
	require.Len(t, networkPolicies, 2)

	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	expectedNetworkPolicy := &cilium.NetworkPolicy{
		EndpointIps:      []string{QAIPv6Addr.String(), QAIPv4Addr.String()},
		EndpointId:       uint64(eQABar.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{},
					{
						RemotePolicies: []uint32{uint32(qaFooSecLblsCtx.ID)},
						L7:             &PNPAllowGETbarLog,
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_config_core.SocketAddress_TCP},
		},
	}
	require.EqualExportedValues(t, expectedNetworkPolicy, qaBarNetworkPolicy)
}

func TestL4L7ShadowingShortCircuitEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testL4L7ShadowingShortCircuit(t)
}

// HTTP rules here have no side effects, so the L4 allow-all rule is
// short-circuiting the HTTP rules (i.e., the network policy sent to
// envoy does not even have the HTTP rules).
func (ds *DaemonSuite) testL4L7ShadowingShortCircuit(t *testing.T) {
	// Prepare the identities necessary for testing
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx, false)
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooSecLblsCtx, false)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{
						// Allow all on port 80 (no proxy)
						CNPAllowTCP80,
					},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblFoo),
						},
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
	}
	for i := range rules {
		rules[i].Sanitize()
	}

	ds.envoyXdsServer.RemoveAllNetworkPolicies()

	ds.policyImport(rules)

	// Prepare endpoints
	cleanup, err := prepareEndpointDirs()
	require.NoError(t, err)
	defer cleanup()

	eQABar := ds.prepareEndpoint(t, qaBarSecLblsCtx, true)
	require.False(t, eQABar.Allows(qaBarSecLblsCtx.ID))
	require.False(t, eQABar.Allows(qaFooSecLblsCtx.ID))

	// Check that both policies have been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(t, nil)
	require.Len(t, networkPolicies, 2)

	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	expectedNetworkPolicy := &cilium.NetworkPolicy{
		EndpointIps:      []string{QAIPv6Addr.String(), QAIPv4Addr.String()},
		EndpointId:       uint64(eQABar.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules:    nil,
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_config_core.SocketAddress_TCP},
		},
	}
	require.EqualExportedValues(t, expectedNetworkPolicy, qaBarNetworkPolicy)
}

func TestL3DependentL7Etcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testL3DependentL7(t)
}

func (ds *DaemonSuite) testL3DependentL7(t *testing.T) {
	// Prepare the identities necessary for testing
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx, false)
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooSecLblsCtx, false)
	qaJoeLbls := labels.Labels{lblJoe.Key: lblJoe, lblQA.Key: lblQA}
	qaJoeSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaJoeLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaJoeSecLblsCtx, false)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblFoo),
						},
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblJoe),
						},
					},
				},
			},
		},
	}
	for i := range rules {
		rules[i].Sanitize()
	}

	ds.envoyXdsServer.RemoveAllNetworkPolicies()

	ds.policyImport(rules)

	// Prepare endpoints
	cleanup, err := prepareEndpointDirs()
	require.NoError(t, err)
	defer cleanup()

	eQABar := ds.prepareEndpoint(t, qaBarSecLblsCtx, true)
	require.False(t, eQABar.Allows(qaBarSecLblsCtx.ID))
	require.False(t, eQABar.Allows(qaFooSecLblsCtx.ID))
	require.True(t, eQABar.Allows(qaJoeSecLblsCtx.ID))

	// Check that both policies have been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(t, nil)
	require.Len(t, networkPolicies, 2)

	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	expectedNetworkPolicy := &cilium.NetworkPolicy{
		EndpointIps:      []string{QAIPv6Addr.String(), QAIPv4Addr.String()},
		EndpointId:       uint64(eQABar.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     0,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint32{uint32(qaJoeSecLblsCtx.ID)},
					},
				},
			},
			{
				Port:     80,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint32{uint32(qaFooSecLblsCtx.ID)},
						L7:             &PNPAllowGETbar,
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_config_core.SocketAddress_TCP},
		},
	}
	require.EqualExportedValues(t, expectedNetworkPolicy, qaBarNetworkPolicy)
}

func TestReplacePolicyEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testReplacePolicy(t)
}

func (ds *DaemonSuite) testReplacePolicy(t *testing.T) {
	lbls := labels.ParseLabelArray("foo", "bar")
	rules := api.Rules{
		{
			Labels:           lbls,
			EndpointSelector: api.NewESFromLabels(lblBar),
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToCIDR: []api.CIDR{
							"1.1.1.1/32",
							"2.2.2.0/24",
						},
					},
				},
			},
		},
		{
			Labels:           lbls,
			EndpointSelector: api.NewESFromLabels(lblBar),
		},
	}
	for i := range rules {
		rules[i].Sanitize()
	}

	ds.policyImport(rules)
	foundRules, _ := ds.d.policy.Search(lbls)
	require.Len(t, foundRules, 2)
	rules[0].Egress = []api.EgressRule{
		{
			EgressCommonRule: api.EgressCommonRule{
				ToCIDR: []api.CIDR{
					"1.1.1.1/32",
					"2.2.2.2/32",
				},
			},
		},
	}
	ds.updatePolicy(&policyTypes.PolicyUpdate{
		Rules:           rules,
		ReplaceByLabels: true,
	})

	foundRules, _ = ds.d.policy.Search(lbls)
	require.Len(t, foundRules, 2)
}

func TestRemovePolicyEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testRemovePolicy(t)
}

func (ds *DaemonSuite) testRemovePolicy(t *testing.T) {
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx, false)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblJoe),
							api.NewESFromLabels(lblPete),
							api.NewESFromLabels(lblFoo),
						},
					},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblFoo),
						},
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblQA),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromRequires: []api.EndpointSelector{
							api.NewESFromLabels(lblQA),
						},
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblProd),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromRequires: []api.EndpointSelector{
							api.NewESFromLabels(lblProd),
						},
					},
				},
			},
		},
	}
	for i := range rules {
		rules[i].Sanitize()
	}

	ds.envoyXdsServer.RemoveAllNetworkPolicies()

	ds.policyImport(rules)

	cleanup, err2 := prepareEndpointDirs()
	require.NoError(t, err2)
	defer cleanup()

	// Create the endpoint and generate its policy.
	e := ds.prepareEndpoint(t, qaBarSecLblsCtx, true)

	// Check that the policy has been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(t, nil)
	require.Len(t, networkPolicies, 2)
	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	require.NotNil(t, qaBarNetworkPolicy)

	// Delete the endpoint.
	e.Delete(endpoint.DeleteConfig{})

	// Check that the policy has been removed from the xDS cache.
	networkPolicies = ds.getXDSNetworkPolicies(t, nil)
	require.Empty(t, networkPolicies)
}

func TestIncrementalPolicyEtcd(t *testing.T) {
	ds := setupDaemonEtcdSuite(t)
	ds.testIncrementalPolicy(t)
}

func (ds *DaemonSuite) testIncrementalPolicy(t *testing.T) {
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx, false)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblJoe),
							api.NewESFromLabels(lblPete),
							api.NewESFromLabels(lblFoo),
						},
					},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(lblFoo),
						},
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblQA),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromRequires: []api.EndpointSelector{
							api.NewESFromLabels(lblQA),
						},
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblProd),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromRequires: []api.EndpointSelector{
							api.NewESFromLabels(lblProd),
						},
					},
				},
			},
		},
	}
	for i := range rules {
		rules[i].Sanitize()
	}

	ds.envoyXdsServer.RemoveAllNetworkPolicies()

	ds.policyImport(rules)

	cleanup, err2 := prepareEndpointDirs()
	require.NoError(t, err2)
	defer cleanup()

	// Create the endpoint and generate its policy.
	eQABar := ds.prepareEndpoint(t, qaBarSecLblsCtx, true)
	// Check that the policy has been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(t, nil)
	require.Len(t, networkPolicies, 2)

	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	require.NotNil(t, qaBarNetworkPolicy)

	// "foo" identity does not exist yet, so there are no ingress policies
	require.Empty(t, qaBarNetworkPolicy.IngressPerPortPolicies)

	// Allocate identities needed for this test
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooID, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooID, false)

	// Regenerate endpoint
	ds.regenerateEndpoint(t, eQABar)

	// Check that the policy has been updated in the xDS cache for the L7
	// proxies. The plumbing of the identity when `AllocateIdentity` is performed
	// down to the `SelectorCache` is asynchronous, so use waiting with a
	// timeout.
	err = testutils.WaitUntil(func() bool {
		networkPolicies = ds.getXDSNetworkPolicies(t, nil)
		if len(networkPolicies) != 2 {
			return false
		}
		qaBarNetworkPolicy = networkPolicies[QAIPv4Addr.String()]
		return qaBarNetworkPolicy != nil && len(qaBarNetworkPolicy.IngressPerPortPolicies) == 2
	}, time.Second*1)
	require.NoError(t, err)
	require.EqualExportedValues(t, &cilium.NetworkPolicy{
		EndpointIps:      []string{QAIPv6Addr.String(), QAIPv4Addr.String()},
		EndpointId:       uint64(eQABar.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     0,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint32{uint32(qaFooID.ID)},
					},
				},
			},
			{
				Port:     80,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint32{uint32(qaFooID.ID)},
						L7:             &PNPAllowGETbar,
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_config_core.SocketAddress_TCP},
		},
	}, qaBarNetworkPolicy)

	// Delete the endpoint.
	eQABar.Delete(endpoint.DeleteConfig{})

	// Check that the policy has been removed from the xDS cache.
	networkPolicies = ds.getXDSNetworkPolicies(t, nil)
	require.Empty(t, networkPolicies)
}
