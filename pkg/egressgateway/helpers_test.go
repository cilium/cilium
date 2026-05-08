// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/podendpointsource"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

type fakeResource[T runtime.Object] chan resource.Event[T]

func (fr fakeResource[T]) sync(tb testing.TB) {
	var sync resource.Event[T]
	sync.Kind = resource.Sync
	fr.process(tb, sync)
}

func (fr fakeResource[T]) process(tb testing.TB, ev resource.Event[T]) {
	tb.Helper()
	if err := fr.processWithError(ev); err != nil {
		tb.Fatal("Failed to process event:", err)
	}
}

func (fr fakeResource[T]) processWithError(ev resource.Event[T]) error {
	errs := make(chan error)
	ev.Done = func(err error) {
		errs <- err
	}
	fr <- ev
	return <-errs
}

func (fr fakeResource[T]) Observe(ctx context.Context, next func(event resource.Event[T]), complete func(error)) {
	complete(errors.New("not implemented"))
}

func (fr fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	if len(opts) > 1 {
		// Ideally we'd only ignore resource.WithRateLimit here, but that
		// isn't possible.
		panic("more than one option is not supported")
	}
	return fr
}

func (fr fakeResource[T]) Store(context.Context) (resource.Store[T], error) {
	return nil, errors.New("not implemented")
}

func addPolicyAndReconcile(tb testing.TB, egressGatewayManager *Manager, policies fakeResource[*Policy], params *policyParams) {
	currentRun := egressGatewayManager.reconciliationEventsCount.Load()
	addPolicy(tb, policies, params)
	waitForReconciliationRun(tb, egressGatewayManager, currentRun)
}

func addPolicy(tb testing.TB, policies fakeResource[*Policy], params *policyParams) {
	tb.Helper()

	policy, _ := newCEGP(params)
	policies.process(tb, resource.Event[*Policy]{
		Kind:   resource.Upsert,
		Object: policy,
	})
}

type policyGatewayParams struct {
	nodeLabels map[string]string
	iface      string
	egressIP   string
}

type policyParams struct {
	name             string
	endpointLabels   map[string]string
	nodeSelectors    map[string]string
	destinationCIDRs []string
	excludedCIDRs    []string
	policyGwParams   []policyGatewayParams
}

func newCEGP(params *policyParams) (*v2.CiliumEgressGatewayPolicy, *PolicyConfig) {
	parsedDestinationCIDRs := make([]netip.Prefix, 0, len(params.destinationCIDRs))
	for _, destCIDR := range params.destinationCIDRs {
		parsedDestinationCIDR, _ := netip.ParsePrefix(destCIDR)
		parsedDestinationCIDRs = append(parsedDestinationCIDRs, parsedDestinationCIDR)
	}

	parsedExcludedCIDRs := make([]netip.Prefix, 0, len(params.excludedCIDRs))
	for _, excludedCIDR := range params.excludedCIDRs {
		parsedExcludedCIDR, _ := netip.ParsePrefix(excludedCIDR)
		parsedExcludedCIDRs = append(parsedExcludedCIDRs, parsedExcludedCIDR)
	}

	policy := &PolicyConfig{
		id: types.NamespacedName{
			Name: params.name,
		},
		dstCIDRs:      parsedDestinationCIDRs,
		excludedCIDRs: parsedExcludedCIDRs,
		endpointSelectors: []*policyTypes.LabelSelector{
			policyTypes.NewLabelSelector(api.EndpointSelector{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			}),
		},
	}
	for _, gwParams := range params.policyGwParams {
		addr, _ := netip.ParseAddr(gwParams.egressIP)
		pwc := policyGatewayConfig{
			iface:    gwParams.iface,
			egressIP: addr,
		}
		if len(gwParams.nodeLabels) != 0 {
			pwc.nodeSelector = policyTypes.NewLabelSelector(api.EndpointSelector{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: gwParams.nodeLabels,
				},
			})
		}
		policy.policyGwConfigs = append(policy.policyGwConfigs, pwc)
	}
	if len(params.nodeSelectors) != 0 {
		policy.nodeSelectors = []*policyTypes.LabelSelector{
			policyTypes.NewLabelSelector(api.EndpointSelector{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.nodeSelectors,
				},
			}),
		}
	}
	if len(params.endpointLabels) != 0 {
		policy.endpointSelectors = []*policyTypes.LabelSelector{
			policyTypes.NewLabelSelector(api.EndpointSelector{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			}),
		}
	}

	// Create destination CIDRs list
	var destinationCIDRs []v2.CIDR
	for _, destCIDR := range params.destinationCIDRs {
		destinationCIDRs = append(destinationCIDRs, v2.CIDR(destCIDR))
	}

	// Create excluded CIDRs list
	excludedCIDRs := []v2.CIDR{}
	for _, excludedCIDR := range params.excludedCIDRs {
		excludedCIDRs = append(excludedCIDRs, v2.CIDR(excludedCIDR))
	}

	cegp := &v2.CiliumEgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: params.name,
		},
		Spec: v2.CiliumEgressGatewayPolicySpec{
			Selectors: []v2.EgressRule{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
			},
			DestinationCIDRs: destinationCIDRs,
			ExcludedCIDRs:    excludedCIDRs,
			EgressGateway: &v2.EgressGateway{
				NodeSelector: &slimv1.LabelSelector{
					MatchLabels: params.policyGwParams[0].nodeLabels,
				},
				Interface: params.policyGwParams[0].iface,
				EgressIP:  params.policyGwParams[0].egressIP,
			},
		},
	}

	// Only populate the list if there is more than one gateway.
	if len(params.policyGwParams) > 1 {
		// EgressGateways contains all the gateways.
		for _, gwParams := range params.policyGwParams {
			gateway := v2.EgressGateway{
				NodeSelector: &slimv1.LabelSelector{
					MatchLabels: gwParams.nodeLabels,
				},
				Interface: gwParams.iface,
				EgressIP:  gwParams.egressIP,
			}
			cegp.Spec.EgressGateways = append(cegp.Spec.EgressGateways, gateway)
		}
	}

	if len(params.nodeSelectors) != 0 {
		cegp.Spec.Selectors[0].NodeSelector = &slimv1.LabelSelector{
			MatchLabels: params.nodeSelectors,
		}
	}

	return cegp, policy
}

// addEndpointAndReconcile delivers a pod endpoint Upsert directly to the
// manager, mirroring what the podendpointsource would emit in production,
// and waits for reconciliation to complete.
func addEndpointAndReconcile(tb testing.TB, egressGatewayManager *Manager, _ fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	currentRun := egressGatewayManager.reconciliationEventsCount.Load()
	addEndpoint(tb, egressGatewayManager, ep)
	waitForReconciliationRun(tb, egressGatewayManager, currentRun)
}

// addEndpoint constructs a PodEndpoint from the given CiliumEndpoint and
// hands it to the manager as an Upsert event. All IPs of the endpoint are
// aggregated into a single event, as the podendpointsource does.
func addEndpoint(tb testing.TB, manager *Manager, ep *k8sTypes.CiliumEndpoint) {
	tb.Helper()

	pe := podEndpointFromCiliumEndpoint(tb, ep)
	if err := manager.handleEndpointEvent(context.Background(), podendpointsource.Event{
		Kind:     podendpointsource.EventKindUpsert,
		Endpoint: pe,
	}); err != nil {
		tb.Fatalf("handleEndpointEvent upsert: %v", err)
	}
}

// deleteEndpointAndReconcile delivers a pod endpoint Delete to the manager
// and waits for reconciliation.
func deleteEndpointAndReconcile(tb testing.TB, egressGatewayManager *Manager, _ fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	currentRun := egressGatewayManager.reconciliationEventsCount.Load()
	deleteEndpoint(tb, egressGatewayManager, ep)
	waitForReconciliationRun(tb, egressGatewayManager, currentRun)
}

// deleteEndpoint hands the manager a whole-endpoint Delete event.
func deleteEndpoint(tb testing.TB, manager *Manager, ep *k8sTypes.CiliumEndpoint) {
	tb.Helper()

	if err := manager.handleEndpointEvent(context.Background(), podendpointsource.Event{
		Kind: podendpointsource.EventKindDelete,
		Endpoint: podendpointsource.PodEndpoint{
			ID: ep.Namespace + "/" + ep.Name,
		},
	}); err != nil {
		tb.Fatalf("handleEndpointEvent delete: %v", err)
	}
}

// podEndpointFromCiliumEndpoint turns a test CiliumEndpoint into the shape
// the podendpointsource would emit. IPs are sorted IPv4-first then IPv6, as
// the production Source does.
func podEndpointFromCiliumEndpoint(tb testing.TB, ep *k8sTypes.CiliumEndpoint) podendpointsource.PodEndpoint {
	tb.Helper()

	var nodeIP string
	if ep.Networking != nil {
		nodeIP = ep.Networking.NodeIP
	}

	pe := podendpointsource.PodEndpoint{
		ID:     ep.Namespace + "/" + ep.Name,
		NodeIP: nodeIP,
	}

	if ep.Networking != nil {
		for _, pair := range ep.Networking.Addressing {
			if pair.IPV4 != "" {
				addr, err := netip.ParseAddr(pair.IPV4)
				if err != nil {
					tb.Fatalf("invalid IPv4 %q: %v", pair.IPV4, err)
				}
				pe.IPs = append(pe.IPs, addr)
			}
			if pair.IPV6 != "" {
				addr, err := netip.ParseAddr(pair.IPV6)
				if err != nil {
					tb.Fatalf("invalid IPv6 %q: %v", pair.IPV6, err)
				}
				pe.IPs = append(pe.IPs, addr)
			}
		}
	}
	slices.SortFunc(pe.IPs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() && !b.Is4():
			return -1
		case !a.Is4() && b.Is4():
			return 1
		default:
			return a.Compare(b)
		}
	})

	if ep.Identity != nil {
		lbls := make(map[string]string, len(ep.Identity.Labels))
		for _, lbl := range ep.Identity.Labels {
			// Identity labels in CEP fixtures are in "k8s:<key>=<value>"
			// form. The source always emits K8s labels in the string-
			// map form (key -> value) after stripping the source prefix;
			// reproduce that here.
			key, value, _ := parseIdentityLabel(lbl)
			if key != "" {
				lbls[key] = value
			}
		}
		pe.Labels = lbls
	}
	return pe
}

// parseIdentityLabel splits a label of the form "src:key=value" into its key
// and value. Labels without an explicit source are accepted as-is.
func parseIdentityLabel(lbl string) (key, value string, ok bool) {
	// Strip optional "<source>:" prefix.
	if i := indexByte(lbl, ':'); i >= 0 {
		lbl = lbl[i+1:]
	}
	if i := indexByte(lbl, '='); i >= 0 {
		return lbl[:i], lbl[i+1:], true
	}
	return lbl, "", true
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func addNodeAndReconcile(tb testing.TB, k *EgressGatewayTestSuite, egressGatewayManager *Manager, node *nodeTypes.Node) {
	currentRun := egressGatewayManager.reconciliationEventsCount.Load()
	k.nodes.process(tb, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node.ToCiliumNode(),
	})
	waitForReconciliationRun(tb, egressGatewayManager, currentRun)
}

func waitForReconciliationRun(tb testing.TB, egressGatewayManager *Manager, currentRun uint64) uint64 {
	for range 100 {
		count := egressGatewayManager.reconciliationEventsCount.Load()
		if count > currentRun {
			return count
		}

		// TODO: investigate why increasing the timeout was necessary to add IPv6 tests.
		time.Sleep(30 * time.Millisecond)
	}

	tb.Fatal("Reconciliation is taking too long to run")
	return 0
}

// Remote-cluster filtering is now the responsibility of the
// podendpointsource, so the egress gateway manager never sees events for
// non-local endpoints. The corresponding test lives alongside the source
// implementation in pkg/podendpointsource.
