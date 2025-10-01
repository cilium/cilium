// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/mac"
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

	policy, _ := newCVP(params)
	policies.process(tb, resource.Event[*Policy]{
		Kind:   resource.Upsert,
		Object: policy,
	})
}

type policyParams struct {
	name             string
	endpointLabels   map[string]string
	podSelectors     map[string]string
	destinationCIDRs []string
	podLabels        map[string]string
	vtepIP           string
	mac              string
}

func newCVP(params *policyParams) (*v2alpha1.CiliumVtepPolicy, *PolicyConfig) {
	parsedDestinationCIDRs := make([]netip.Prefix, 0, len(params.destinationCIDRs))
	for _, destCIDR := range params.destinationCIDRs {
		parsedDestinationCIDR, _ := netip.ParsePrefix(destCIDR)
		parsedDestinationCIDRs = append(parsedDestinationCIDRs, parsedDestinationCIDR)
	}

	parsedVtepIp, _ := netip.ParseAddr(params.vtepIP)
	parsedMac, _ := mac.ParseMAC(params.mac)

	policy := &PolicyConfig{
		id: types.NamespacedName{
			Name: params.name,
		},
		dstCIDRs: parsedDestinationCIDRs,
		vtepConfig: vtepConfig{
			vtepIP:  parsedVtepIp,
			vtepMAC: parsedMac,
		},
	}

	if len(params.podSelectors) != 0 {
		policy.podSelectors = []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.podSelectors,
				},
			},
		}
	}

	// Create destination CIDRs list
	var destinationCIDRs []v2alpha1.CIDR
	for _, destCIDR := range params.destinationCIDRs {
		destinationCIDRs = append(destinationCIDRs, v2alpha1.CIDR(destCIDR))
	}

	cvp := &v2alpha1.CiliumVtepPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: params.name,
		},
		Spec: v2alpha1.CiliumVtepPolicySpec{
			Selectors: []v2alpha1.CiliumVtepPolicyRules{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
			},
			DestinationCIDRs: destinationCIDRs,
			ExternalVTEP: &v2alpha1.ExternalVTEP{
				IP:  params.vtepIP,
				MAC: v2alpha1.MAC(params.mac),
			},
		},
		TypeMeta: metav1.TypeMeta{},
	}

	if len(params.podSelectors) != 0 {
		cvp.Spec.Selectors[0].PodSelector = &slimv1.LabelSelector{
			MatchLabels: params.podSelectors,
		}
	}

	return cvp, policy
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
