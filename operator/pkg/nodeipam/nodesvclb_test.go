// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-3",
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "2001:0000::3"},
					{Type: corev1.NodeExternalIP, Address: "42.0.0.3"},
				},
			},
		},

		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "node-4-excluded",
				DeletionTimestamp: &metav1.Time{Time: time.Now()},
				Finalizers:        []string{"myfinalizer"},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "2001:0000:4"},
					{Type: corev1.NodeExternalIP, Address: "42.0.0.4"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-5-excluded",
				Labels: map[string]string{
					corev1.LabelNodeExcludeBalancers: "",
				},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "2001:0000:5"},
					{Type: corev1.NodeExternalIP, Address: "42.0.0.5"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-6-excluded",
			},
			Spec: corev1.NodeSpec{
				Taints: []corev1.Taint{
					{Key: toBeDeletedTaint},
				},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "2001:0000:6"},
					{Type: corev1.NodeExternalIP, Address: "42.0.0.6"},
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
				{NodeName: ptr.To("node-1")},
				{NodeName: ptr.To("node-2"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)}},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv4-internal",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeLoadBalancer,
				IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol},
				LoadBalancerClass:     &nodeSvcLBClass,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv4-external",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ipv4-external"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: ptr.To("node-1")},
				{NodeName: ptr.To("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv4-external",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeLoadBalancer,
				IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol},
				LoadBalancerClass:     &nodeSvcLBClass,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-internal",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ipv6-internal"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: ptr.To("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-internal",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeLoadBalancer,
				IPFamilies:            []corev1.IPFamily{corev1.IPv6Protocol},
				LoadBalancerClass:     &nodeSvcLBClass,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-external",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ipv6-external"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: ptr.To("node-1")},
				{NodeName: ptr.To("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ipv6-external",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeLoadBalancer,
				IPFamilies:            []corev1.IPFamily{corev1.IPv6Protocol},
				LoadBalancerClass:     &nodeSvcLBClass,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dualstack-external",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "dualstack-external"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: ptr.To("node-1")},
				{NodeName: ptr.To("node-2")},
				{NodeName: ptr.To("does-not-exist")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dualstack-external",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeLoadBalancer,
				IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
				LoadBalancerClass:     &nodeSvcLBClass,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			},
		},

		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "etp-cluster",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeLoadBalancer,
				IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol},
				LoadBalancerClass:     &nodeSvcLBClass,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
			},
		},

		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-supported-1",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "not-supported-1"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{NodeName: ptr.To("node-1")},
				{NodeName: ptr.To("node-2")},
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
				{NodeName: ptr.To("node-1")},
				{NodeName: ptr.To("node-2")},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-supported-2",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
				LoadBalancerClass:     &nodeSvcLBClass,
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			},
			Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{IP: "100.100.100.100"}},
			}},
		},

		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default-ipam",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:       corev1.ServiceTypeLoadBalancer,
				IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
			},
		},
	}

	nodeSvcLabelFixtures = []client.Object{
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-1",
				Labels: map[string]string{"ingress-ready": "true", "all": "true", "group": "first"},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-2",
				Labels: map[string]string{"all": "true", "group": "notfirst", "test/label": "is-good"},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "10.0.0.2"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-3",
				Labels: map[string]string{"all": "true", "group": "notfirst"},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "10.0.0.3"},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svclabels",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Type:              corev1.ServiceTypeLoadBalancer,
				IPFamilies:        []corev1.IPFamily{corev1.IPv4Protocol},
				LoadBalancerClass: &nodeSvcLBClass,
			},
		},
	}
)

func Test_nodeIPAM_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithObjects(nodeSvcLbFixtures...).
		WithStatusSubresource(&corev1.Service{}).
		Build()
	r := &nodeSvcLBReconciler{Client: c, Logger: hivetest.Logger(t)}

	t.Run("unsupported service reset", func(t *testing.T) {
		for _, name := range []string{"not-supported-1", "not-supported-2"} {
			key := types.NamespacedName{
				Name:      name,
				Namespace: "default",
			}
			result, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			svc := &corev1.Service{}
			err = c.Get(t.Context(), key, svc)

			require.NoError(t, err)
			// It did not change the IPs already advertised
			require.Len(t, svc.Status.LoadBalancer.Ingress, 1)
			require.Equal(t, "100.100.100.100", svc.Status.LoadBalancer.Ingress[0].IP)
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
			result, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			svc := &corev1.Service{}
			err = c.Get(t.Context(), key, svc)

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
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svc := &corev1.Service{}
		err = c.Get(t.Context(), key, svc)

		require.NoError(t, err)
		require.Len(t, svc.Status.LoadBalancer.Ingress, 2)
		require.Equal(t, "2001:0000::1", svc.Status.LoadBalancer.Ingress[0].IP)
		require.Equal(t, "42.0.0.2", svc.Status.LoadBalancer.Ingress[1].IP)
	})

	t.Run("external traffic policy cluster", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "etp-cluster",
			Namespace: "default",
		}
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svc := &corev1.Service{}
		err = c.Get(t.Context(), key, svc)

		require.NoError(t, err)
		require.Len(t, svc.Status.LoadBalancer.Ingress, 2)
		require.Equal(t, "42.0.0.2", svc.Status.LoadBalancer.Ingress[0].IP)
		require.Equal(t, "42.0.0.3", svc.Status.LoadBalancer.Ingress[1].IP)
	})
}

func Test_nodeIPAM_defaultIPAM_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithObjects(nodeSvcLbFixtures...).
		WithStatusSubresource(&corev1.Service{}).
		Build()
	r := &nodeSvcLBReconciler{Client: c, DefaultIPAM: true, Logger: hivetest.Logger(t)}

	key := types.NamespacedName{
		Name:      "default-ipam",
		Namespace: "default",
	}
	result, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: key,
	})

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result, "Result should be empty")

	svc := &corev1.Service{}
	err = c.Get(t.Context(), key, svc)

	require.NoError(t, err)
	require.Len(t, svc.Status.LoadBalancer.Ingress, 2)
	require.Equal(t, "42.0.0.2", svc.Status.LoadBalancer.Ingress[0].IP)
	require.Equal(t, "42.0.0.3", svc.Status.LoadBalancer.Ingress[1].IP)
}

func Test_nodeIPAM_CiliumResources_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithObjects(nodeSvcLabelFixtures...).
		WithStatusSubresource(&corev1.Service{}).
		Build()
	r := &nodeSvcLBReconciler{Client: c, Logger: hivetest.Logger(t)}

	key := types.NamespacedName{
		Name:      "svclabels",
		Namespace: "default",
	}

	t.Run("Managed Resource", func(t *testing.T) {
		ctx := t.Context()
		result, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svc := &corev1.Service{}
		err = c.Get(ctx, key, svc)

		require.NoError(t, err)
		require.Len(t, svc.Status.LoadBalancer.Ingress, 3)
		var ips []string
		for _, v := range svc.Status.LoadBalancer.Ingress {
			ips = append(ips, v.IP)
		}
		require.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, ips)
	})

	t.Run("Node Label Filter", func(t *testing.T) {
		ctx := t.Context()

		for _, param := range []struct {
			labelFilter string
			results     []string
		}{
			{labelFilter: "all=true", results: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
			{labelFilter: "ingress-ready=true", results: []string{"10.0.0.1"}},
			{labelFilter: "group=notfirst", results: []string{"10.0.0.2", "10.0.0.3"}},
			{labelFilter: "group notin (first),test/label=is-good", results: []string{"10.0.0.2"}},
		} {
			svc := &corev1.Service{}
			_ = c.Get(ctx, key, svc)
			// Add the label to the service which should return on the first node
			svc.Annotations = map[string]string{nodeSvcLBMatchLabelsAnnotation: param.labelFilter}
			_ = c.Update(ctx, svc)
			result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			svc = &corev1.Service{}
			err = c.Get(ctx, key, svc)

			require.NoError(t, err)
			require.NotNil(t, svc.Annotations[nodeSvcLBMatchLabelsAnnotation])
			require.Len(t, svc.Status.LoadBalancer.Ingress, len(param.results))

			var ips []string
			for _, v := range svc.Status.LoadBalancer.Ingress {
				ips = append(ips, v.IP)
			}
			require.Equal(t, ips, param.results)
		}
	})

	t.Run("Bad Node Label Filter", func(t *testing.T) {
		ctx := t.Context()
		svc := &corev1.Service{}
		_ = c.Get(ctx, key, svc)
		// Add the label to the service which should return on the first node
		svc.Annotations = map[string]string{nodeSvcLBMatchLabelsAnnotation: "this is completely/bad=!;lf"}
		_ = c.Update(ctx, svc)
		result, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: key,
		})

		require.Error(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")
	})

	t.Run("Ensure Warning raised if no Nodes found using configured label selector", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		r.Logger = logger

		ctx := t.Context()
		svc := &corev1.Service{}
		_ = c.Get(ctx, key, svc)
		// Add the label to the service which should return on the first node
		svc.Annotations = map[string]string{nodeSvcLBMatchLabelsAnnotation: "foo=bar"}
		_ = c.Update(ctx, svc)
		result, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")
		fmt.Println(buf.String())
		require.Contains(t, buf.String(), "level=WARN msg=\"No Nodes found with configured label selector\"")
	})
}
