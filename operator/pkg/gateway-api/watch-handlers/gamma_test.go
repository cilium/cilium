// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// TestEnqueueRequestForGAMMAHTTPRouteOnlyMatchesServiceParents ensures that only
// core Service parents resolve to a GAMMA Service. Any other parent kind sharing
// a name with a Service in the same namespace must not enqueue that Service.
func TestEnqueueRequestForGAMMAHTTPRouteOnlyMatchesServiceParents(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	// A valid GAMMA Service whose name collides with the ListenerSet and the
	// Gateway referenced as parents below.
	gammaService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-name",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
	}

	serviceParent := func(name string) gatewayv1.ParentReference {
		return gatewayv1.ParentReference{
			Group: ptr.To[gatewayv1.Group](corev1.GroupName),
			Kind:  ptr.To[gatewayv1.Kind]("Service"),
			Name:  gatewayv1.ObjectName(name),
		}
	}

	tests := []struct {
		name   string
		parent gatewayv1.ParentReference
		want   []types.NamespacedName
	}{
		{
			name:   "core Service parent enqueues the GAMMA Service",
			parent: serviceParent("shared-name"),
			want:   []types.NamespacedName{{Namespace: "default", Name: "shared-name"}},
		},
		{
			name: "ListenerSet parent does not enqueue a same-named Service",
			parent: gatewayv1.ParentReference{
				Group: ptr.To[gatewayv1.Group](gatewayv1.GroupName),
				Kind:  ptr.To[gatewayv1.Kind]("ListenerSet"),
				Name:  "shared-name",
			},
		},
		{
			name: "Gateway parent does not enqueue a same-named Service",
			parent: gatewayv1.ParentReference{
				Group: ptr.To[gatewayv1.Group](gatewayv1.GroupName),
				Kind:  ptr.To[gatewayv1.Kind]("Gateway"),
				Name:  "shared-name",
			},
		},
		{
			name: "unrelated parent kind does not enqueue a same-named Service",
			parent: gatewayv1.ParentReference{
				Group: ptr.To[gatewayv1.Group]("example.com"),
				Kind:  ptr.To[gatewayv1.Kind]("SomeOtherKind"),
				Name:  "shared-name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{tt.parent},
					},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(gammaService, route).
				Build()

			handler := EnqueueRequestForGAMMAHTTPRoute(fakeClient, hivetest.Logger(t))
			queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
			defer queue.ShutDown()

			handler.Create(t.Context(), event.TypedCreateEvent[client.Object]{Object: route}, queue)

			var got []types.NamespacedName
			for queue.Len() > 0 {
				item, shutdown := queue.Get()
				require.False(t, shutdown)
				got = append(got, item.NamespacedName)
				queue.Done(item)
			}

			require.ElementsMatch(t, tt.want, got)
		})
	}
}
