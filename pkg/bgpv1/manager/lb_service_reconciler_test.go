// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"net/netip"
	"testing"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestLBServiceReconciler(t *testing.T) {
	blueSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	redSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}}
	svc1Name := resource.Key{Name: "svc-1", Namespace: "default"}
	svc1NonDefaultName := resource.Key{Name: "svc-1", Namespace: "non-default"}
	svc2NonDefaultName := resource.Key{Name: "svc-2", Namespace: "non-default"}
	ingressV4 := "192.168.0.1"
	ingressV4_2 := "192.168.0.2"
	ingressV4Prefix := ingressV4 + "/32"
	ingressV4Prefix_2 := ingressV4_2 + "/32"
	ingressV6 := "fd00:192:168::1"
	ingressV6Prefix := ingressV6 + "/128"

	svc1 := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      svc1Name.Name,
			Namespace: svc1Name.Namespace,
			Labels:    blueSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4,
					},
				},
			},
		},
	}

	svc1TwoIngress := svc1.DeepCopy()
	svc1TwoIngress.Status.LoadBalancer.Ingress =
		append(svc1TwoIngress.Status.LoadBalancer.Ingress,
			slim_corev1.LoadBalancerIngress{IP: ingressV6})

	svc1RedLabel := svc1.DeepCopy()
	svc1RedLabel.ObjectMeta.Labels = redSelector.MatchLabels

	svc1NonDefault := svc1.DeepCopy()
	svc1NonDefault.Namespace = svc1NonDefaultName.Namespace
	svc1NonDefault.Status.LoadBalancer.Ingress[0] = slim_corev1.LoadBalancerIngress{IP: ingressV4_2}

	svc1NonLB := svc1.DeepCopy()
	svc1NonLB.Spec.Type = slim_corev1.ServiceTypeClusterIP

	svc1ETPLocal := svc1.DeepCopy()
	svc1ETPLocal.Spec.ExternalTrafficPolicy = slim_corev1.ServiceExternalTrafficPolicyLocal

	svc1ETPLocalTwoIngress := svc1TwoIngress.DeepCopy()
	svc1ETPLocalTwoIngress.Spec.ExternalTrafficPolicy = slim_corev1.ServiceExternalTrafficPolicyLocal

	svc1IPv6ETPLocal := svc1.DeepCopy()
	svc1IPv6ETPLocal.Status.LoadBalancer.Ingress[0] = slim_corev1.LoadBalancerIngress{IP: ingressV6}
	svc1IPv6ETPLocal.Spec.ExternalTrafficPolicy = slim_corev1.ServiceExternalTrafficPolicyLocal

	svc1LbClass := svc1.DeepCopy()
	svc1LbClass.Spec.LoadBalancerClass = pointer.String(v2alpha1api.BGPLoadBalancerClass)

	svc1UnsupportedClass := svc1LbClass.DeepCopy()
	svc1UnsupportedClass.Spec.LoadBalancerClass = pointer.String("io.vendor/unsupported-class")

	svc2NonDefault := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      svc2NonDefaultName.Name,
			Namespace: svc2NonDefaultName.Namespace,
			Labels:    blueSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4_2,
					},
				},
			},
		},
	}

	eps1IPv4Local := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
		},
	}

	eps1IPv4Remote := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
		},
	}

	eps1IPv4Mixed := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
		},
	}

	eps1IPv6Local := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv6",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv6",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("fd00:10::1"): {
				NodeName: "node1",
			},
		},
	}

	eps1IPv6Remote := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv6",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv6",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("fd00:10::2"): {
				NodeName: "node2",
			},
		},
	}

	eps1IPv6Mixed := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("fd00:10::1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("fd00:10::2"): {
				NodeName: "node2",
			},
		},
	}

	var table = []struct {
		// name of the test case
		name string
		// The service selector of the vRouter
		oldServiceSelector *slim_metav1.LabelSelector
		// The service selector of the vRouter
		newServiceSelector *slim_metav1.LabelSelector
		// the advertised PodCIDR blocks the test begins with
		advertised map[resource.Key][]string
		// the services which will be "upserted" in the diffstore
		upsertedServices []*slim_corev1.Service
		// the services which will be "deleted" in the diffstore
		deletedServices []resource.Key
		// the endpoints which will be "upserted" in the diffstore
		upsertedEndpoints []*k8s.Endpoints
		// the updated PodCIDR blocks to reconcile, these are string encoded
		// for the convenience of attaching directly to the NodeSpec.PodCIDRs
		// field.
		updated map[resource.Key][]string
		// error nil or not
		err error
	}{
		// Add 1 ingress
		{
			name:               "lb-svc-1-ingress",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         make(map[resource.Key][]string),
			upsertedServices:   []*slim_corev1.Service{svc1},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// Add 2 ingress
		{
			name:               "lb-svc-2-ingress",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         make(map[resource.Key][]string),
			upsertedServices:   []*slim_corev1.Service{svc1TwoIngress},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
		// Delete service
		{
			name:               "delete-svc",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			deletedServices: []resource.Key{
				svc1Name,
			},
			updated: map[resource.Key][]string{},
		},
		// Update service to no longer match
		{
			name:               "update-service-no-match",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			upsertedServices: []*slim_corev1.Service{svc1RedLabel},
			updated:          map[resource.Key][]string{},
		},
		// Update vRouter to no longer match
		{
			name:               "update-vrouter-selector",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &redSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			upsertedServices: []*slim_corev1.Service{svc1},
			updated:          map[resource.Key][]string{},
		},
		// 1 -> 2 ingress
		{
			name:               "update-1-to-2-ingress",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			upsertedServices: []*slim_corev1.Service{svc1TwoIngress},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
		// No selector
		{
			name:               "no-selector",
			oldServiceSelector: nil,
			newServiceSelector: nil,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1},
			updated:            map[resource.Key][]string{},
		},
		// Namespace selector
		{
			name:               "svc-namespace-selector",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.namespace": "default"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.namespace": "default"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				svc1,
				svc2NonDefault,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// Service name selector
		{
			name:               "svc-name-selector",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-1"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-1"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				svc1,
				svc1NonDefault,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
				svc1NonDefaultName: {
					ingressV4Prefix_2,
				},
			},
		},
		// BGP load balancer class with matching selectors for service.
		{
			name:               "lb-class-and-selectors",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1LbClass},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// BGP load balancer class with no selectors for service.
		{
			name:               "lb-class-no-selectors",
			oldServiceSelector: nil,
			newServiceSelector: nil,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1LbClass},
			updated:            map[resource.Key][]string{},
		},
		// BGP load balancer class with selectors for a different service.
		{
			name:               "lb-class-with-diff-selectors",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-2"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-2"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1LbClass},
			updated:            map[resource.Key][]string{},
		},
		// Unsupported load balancer class with matching selectors for service.
		{
			name:               "unsupported-lb-class-with-selectors",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1UnsupportedClass},
			updated:            map[resource.Key][]string{},
		},
		// Unsupported load balancer class with no matching selectors for service.
		{
			name:               "unsupported-lb-class-with-no-selectors",
			oldServiceSelector: nil,
			newServiceSelector: nil,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1UnsupportedClass},
			updated:            map[resource.Key][]string{},
		},
		// No-LB service
		{
			name:               "non-lb svc",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1NonLB},
			updated:            map[resource.Key][]string{},
		},
		// Service without endpoints
		{
			name:               "etp-local-no-endpoints",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{},
			updated:            map[resource.Key][]string{},
		},
		// externalTrafficPolicy=Local && IPv4 && single slice && local endpoint
		{
			name:               "etp-local-ipv4-single-slice-local",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv4Local},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && IPv4 && single slice && remote endpoint
		{
			name:               "etp-local-ipv4-single-slice-remote",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv4Remote},
			updated:            map[resource.Key][]string{},
		},
		// externalTrafficPolicy=Local && IPv4 && single slice && mixed endpoint
		{
			name:               "etp-local-ipv4-single-slice-mixed",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv4Mixed},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && IPv6 && single slice && local endpoint
		{
			name:               "etp-local-ipv6-single-slice-local",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1IPv6ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv6Local},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV6Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && IPv6 && single slice && remote endpoint
		{
			name:               "etp-local-ipv6-single-slice-remote",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1IPv6ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv6Remote},
			updated:            map[resource.Key][]string{},
		},
		// externalTrafficPolicy=Local && IPv6 && single slice && mixed endpoint
		{
			name:               "etp-local-ipv6-single-slice-mixed",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1IPv6ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv6Mixed},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV6Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && Dual && two slices && local endpoint
		{
			name:               "etp-local-dual-two-slices-local",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocalTwoIngress},
			upsertedEndpoints: []*k8s.Endpoints{
				eps1IPv4Local,
				eps1IPv6Local,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && Dual && two slices && remote endpoint
		{
			name:               "etp-local-dual-two-slices-remote",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocalTwoIngress},
			upsertedEndpoints: []*k8s.Endpoints{
				eps1IPv4Remote,
				eps1IPv6Remote,
			},
			updated: map[resource.Key][]string{
				svc1Name: {},
			},
		},
		// externalTrafficPolicy=Local && Dual && two slices && mixed endpoint
		{
			name:               "etp-local-dual-two-slices-mixed",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocalTwoIngress},
			upsertedEndpoints: []*k8s.Endpoints{
				eps1IPv4Mixed,
				eps1IPv6Mixed,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// setup our test server, create a BgpServer, advertise the tt.advertised
			// networks, and store each returned Advertisement in testSC.PodCIDRAnnouncements
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:        64125,
				Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector: tt.oldServiceSelector,
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = oldc

			diffstore := newFakeDiffStore[*slim_corev1.Service]()
			for _, obj := range tt.upsertedServices {
				diffstore.Upsert(obj)
			}
			for _, key := range tt.deletedServices {
				diffstore.Delete(key)
			}

			epDiffStore := newFakeDiffStore[*k8s.Endpoints]()
			for _, obj := range tt.upsertedEndpoints {
				epDiffStore.Upsert(obj)
			}

			reconciler := NewLBServiceReconciler(diffstore, epDiffStore).Reconciler.(*LBServiceReconciler)
			serviceAnnouncements := reconciler.getMetadata(testSC)

			for svcKey, cidrs := range tt.advertised {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					advrtResp, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
						Path: types.NewPathForPrefix(prefix),
					})
					if err != nil {
						t.Fatalf("failed to advertise initial svc lb cidr routes: %v", err)
					}

					serviceAnnouncements[svcKey] = append(serviceAnnouncements[svcKey], advrtResp.Path)
				}
			}

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:        64125,
				Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector: tt.newServiceSelector,
			}

			err = reconciler.Reconcile(context.Background(), ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
				CiliumNode: &v2api.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node1",
					},
				},
			})
			if err != nil {
				t.Fatalf("failed to reconcile new lb svc advertisements: %v", err)
			}

			// if we disable exports of pod cidr ensure no advertisements are
			// still present.
			if tt.newServiceSelector == nil && !containsLbClass(tt.upsertedServices) {
				if len(serviceAnnouncements) > 0 {
					t.Fatal("disabled export but advertisements still present")
				}
			}

			log.Printf("%+v %+v", serviceAnnouncements, tt.updated)

			// ensure we see tt.updated in testSC.ServiceAnnouncements
			for svcKey, cidrs := range tt.updated {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					var seen bool
					for _, advrt := range serviceAnnouncements[svcKey] {
						if advrt.NLRI.String() == prefix.String() {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("failed to advertise %v", cidr)
					}
				}
			}

			// ensure testSC.PodCIDRAnnouncements does not contain advertisements
			// not in tt.updated
			for svcKey, advrts := range serviceAnnouncements {
				for _, advrt := range advrts {
					var seen bool
					for _, cidr := range tt.updated[svcKey] {
						if advrt.NLRI.String() == cidr {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("unwanted advert %+v", advrt)
					}
				}
			}

		})
	}
}

func containsLbClass(svcs []*slim_corev1.Service) bool {
	for _, svc := range svcs {
		if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == v2alpha1api.BGPLoadBalancerClass {
			return true
		}
	}
	return false
}
