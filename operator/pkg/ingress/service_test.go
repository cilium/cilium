// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_handleEvent(t *testing.T) {

	t.Run("unknown event", func(t *testing.T) {
		sm := serviceManager{
			ingressQueue: newQueue(),
		}
		err := sm.handleEvent(ingressAddedEvent{})
		require.Error(t, err)
	})

	t.Run("delete service", func(t *testing.T) {
		sm := serviceManager{
			ingressQueue: newQueue(),
		}
		err := sm.handleEvent(serviceDeletedEvent{service: &slim_corev1.Service{}})
		require.NoError(t, err)
		require.Empty(t, sm.ingressQueue.Len())
	})

	t.Run("add service", func(t *testing.T) {
		t.Run("no ops", func(t *testing.T) {
			sm := serviceManager{
				ingressQueue: newQueue(),
			}
			err := sm.handleEvent(serviceAddedEvent{service: &slim_corev1.Service{}})
			require.NoError(t, err)
			require.Empty(t, sm.ingressQueue.Len())
		})

		t.Run("with load balancer status", func(t *testing.T) {
			sm := serviceManager{
				ingressQueue: newQueue(),
			}
			err := sm.handleEvent(serviceAddedEvent{service: &slim_corev1.Service{
				Status: slim_corev1.ServiceStatus{
					LoadBalancer: slim_corev1.LoadBalancerStatus{
						Ingress: []slim_corev1.LoadBalancerIngress{
							{
								IP: "dummy-loadbalance.com",
							},
						},
					},
				},
			}})
			require.NoError(t, err)
			require.Equal(t, sm.ingressQueue.Len(), 1)
		})
	})

	t.Run("update service", func(t *testing.T) {
		t.Run("no ops", func(t *testing.T) {
			sm := serviceManager{
				ingressQueue: newQueue(),
			}
			err := sm.handleEvent(serviceUpdatedEvent{
				oldService: &slim_corev1.Service{},
				newService: &slim_corev1.Service{}},
			)
			require.NoError(t, err)
			require.Empty(t, sm.ingressQueue.Len())
		})

		t.Run("with load balancer status", func(t *testing.T) {
			sm := serviceManager{
				ingressQueue: newQueue(),
			}
			err := sm.handleEvent(serviceUpdatedEvent{
				oldService: &slim_corev1.Service{},
				newService: &slim_corev1.Service{
					Status: slim_corev1.ServiceStatus{
						LoadBalancer: slim_corev1.LoadBalancerStatus{
							Ingress: []slim_corev1.LoadBalancerIngress{
								{
									IP: "dummy-loadbalance.com",
								},
							},
						},
					},
				}},
			)
			require.NoError(t, err)
			require.Equal(t, sm.ingressQueue.Len(), 1)
		})

		t.Run("with load balancer status but being deleted", func(t *testing.T) {
			sm := serviceManager{
				ingressQueue: newQueue(),
			}
			err := sm.handleEvent(serviceUpdatedEvent{
				oldService: &slim_corev1.Service{},
				newService: &slim_corev1.Service{
					ObjectMeta: slim_metav1.ObjectMeta{
						DeletionTimestamp: &slim_metav1.Time{},
					},
					Status: slim_corev1.ServiceStatus{
						LoadBalancer: slim_corev1.LoadBalancerStatus{
							Ingress: []slim_corev1.LoadBalancerIngress{
								{
									IP: "dummy-loadbalance.com",
								},
							},
						},
					},
				}},
			)
			require.NoError(t, err)
			require.Equal(t, sm.ingressQueue.Len(), 0)
		})
	})
}

func newQueue() workqueue.RateLimitingInterface {
	return workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.DefaultControllerRateLimiter(),
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(5), 10)}), "fakeQueue")
}
