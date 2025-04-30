// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/policy/api"
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
		endpointSelectors: []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
		},
	}
	for _, gwParams := range params.policyGwParams {
		addr, _ := netip.ParseAddr(gwParams.egressIP)
		pwc := policyGatewayConfig{
			iface:    gwParams.iface,
			egressIP: addr,
		}
		if len(gwParams.nodeLabels) != 0 {
			pwc.nodeSelector = api.EndpointSelector{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: gwParams.nodeLabels,
				},
			}
		}
		policy.policyGwConfigs = append(policy.policyGwConfigs, pwc)
	}
	if len(params.nodeSelectors) != 0 {
		policy.nodeSelectors = []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.nodeSelectors,
				},
			},
		}
	}
	if len(params.endpointLabels) != 0 {
		policy.endpointSelectors = []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
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

func addEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Upsert,
		Object: ep,
	})
}

func deleteEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Delete,
		Object: ep,
	})
}
