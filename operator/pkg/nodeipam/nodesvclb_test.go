// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/cilium/pkg/logging"
)

var (
	nodeSvcLbFixtures = []client.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-1",
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					{Type: corev1.NodeExternalIP, Address: "2001:0000::1"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-2",
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "fc00::2"},
					{Type: corev1.NodeExternalIP, Address: "42.0.0.2"},
				},
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv4-internal",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ipv4-internal"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: stringPtr("node-1")},
				{NodeName: stringPtr("node-2"), Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(false)}},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv4-internal",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				IPFamilies:        []corev1.IPFamily{corev1.IPv4Protocol},
				LoadBalancerClass: &nodeSvcLBClass,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv4-external",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ipv4-external"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: stringPtr("node-1")},
				{NodeName: stringPtr("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv4-external",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				IPFamilies:        []corev1.IPFamily{corev1.IPv4Protocol},
				LoadBalancerClass: &nodeSvcLBClass,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-internal",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ipv6-internal"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: stringPtr("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-internal",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				IPFamilies:        []corev1.IPFamily{corev1.IPv6Protocol},
				LoadBalancerClass: &nodeSvcLBClass,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-external",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ipv6-external"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: stringPtr("node-1")},
				{NodeName: stringPtr("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-external",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				IPFamilies:        []corev1.IPFamily{corev1.IPv6Protocol},
				LoadBalancerClass: &nodeSvcLBClass,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dualstack-external",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "dualstack-external"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: stringPtr("node-1")},
				{NodeName: stringPtr("node-2")},
				{NodeName: stringPtr("does-not-exist")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dualstack-external",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				IPFamilies:        []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
				LoadBalancerClass: &nodeSvcLBClass,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-supported-1",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "not-supported-1"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: stringPtr("node-1")},
				{NodeName: stringPtr("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-supported-1",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:       corev1.ServiceTypeLoadBalancer,
				IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
			},
			Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{IP: "100.100.100.100"}},
			}},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-supported-2",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "not-supported-2"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: stringPtr("node-1")},
				{NodeName: stringPtr("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-supported-2",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				IPFamilies:        []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
				LoadBalancerClass: &nodeSvcLBClass,
			},
			Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{IP: "100.100.100.100"}},
			}},
		},
	}
)

func stringPtr(str string) *string {
	return &str
}
func boolPtr(boolean bool) *bool {
	return &boolean
}

func Test_httpRouteReconciler_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithObjects(nodeSvcLbFixtures...).
		WithStatusSubresource(&corev1.Service{}).
		Build()
	r := &nodeSvcLBReconciler{Client: c, Logger: logging.DefaultLogger}

	t.Run("unsupported service reset", func(t *testing.T) {
		for _, name := range []string{"not-supported-1", "not-supported-2"} {
			key := types.NamespacedName{
				Name:      name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			svc := &corev1.Service{}
			err = c.Get(context.Background(), key, svc)

			require.NoError(t, err)
			// It did not change the IPs already advertised
			require.Len(t, svc.Status.LoadBalancer.Ingress, 1)
			require.Equal(t, svc.Status.LoadBalancer.Ingress[0].IP, "100.100.100.100")
		}
	})

	t.Run("single address test in single stack", func(t *testing.T) {
		for _, param := range []struct {
			name    string
			address string
		}{
			{name: "ipv4-internal", address: "10.0.0.1"},
			{name: "ipv4-external", address: "42.0.0.2"},
			{name: "ipv6-internal", address: "fc00::2"},
			{name: "ipv6-external", address: "2001:0000::1"},
		} {
			key := types.NamespacedName{
				Name:      param.name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			svc := &corev1.Service{}
			err = c.Get(context.Background(), key, svc)

			require.NoError(t, err)
			require.Len(t, svc.Status.LoadBalancer.Ingress, 1)
			require.Equal(t, svc.Status.LoadBalancer.Ingress[0].IP, param.address)
		}
	})

	t.Run("dual stack", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "dualstack-external",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svc := &corev1.Service{}
		err = c.Get(context.Background(), key, svc)

		require.NoError(t, err)
		require.Len(t, svc.Status.LoadBalancer.Ingress, 2)
		require.Equal(t, svc.Status.LoadBalancer.Ingress[0].IP, "2001:0000::1")
		require.Equal(t, svc.Status.LoadBalancer.Ingress[1].IP, "42.0.0.2")
	})
}
