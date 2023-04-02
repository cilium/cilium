// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_ingressClassHandleEvent(t *testing.T) {

	t.Run("unknown event", func(t *testing.T) {
		i := ingressClassManager{
			ingressQueue: newQueue(),
		}
		err := i.handleEvent(ingressAddedEvent{})
		require.Error(t, err)
	})

	t.Run("delete ingressClass", func(t *testing.T) {
		i := ingressClassManager{
			ingressQueue: newQueue(),
		}
		err := i.handleEvent(ingressClassDeletedEvent{ingressClass: &slim_networkingv1.IngressClass{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: ciliumIngressClassName,
			},
		}})
		require.NoError(t, err)
		require.Equal(t, 1, i.ingressQueue.Len())
	})

	t.Run("add ingressClass", func(t *testing.T) {
		t.Run("no ops if name is not us", func(t *testing.T) {
			i := ingressClassManager{
				ingressQueue: newQueue(),
			}
			err := i.handleEvent(ingressClassAddedEvent{ingressClass: &slim_networkingv1.IngressClass{}})
			require.NoError(t, err)
			require.Empty(t, i.ingressQueue.Len())
		})

		t.Run("with correct name", func(t *testing.T) {
			i := ingressClassManager{
				ingressQueue: newQueue(),
			}
			err := i.handleEvent(ingressClassAddedEvent{ingressClass: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: ciliumIngressClassName,
				},
			}})
			require.NoError(t, err)
			require.Equal(t, 1, i.ingressQueue.Len())
		})
	})

	t.Run("update ingressClass", func(t *testing.T) {
		t.Run("no ops if not ours", func(t *testing.T) {
			i := ingressClassManager{
				ingressQueue: newQueue(),
			}
			err := i.handleEvent(ingressClassUpdatedEvent{
				oldIngressClass: &slim_networkingv1.IngressClass{},
				newIngressClass: &slim_networkingv1.IngressClass{},
			})
			require.NoError(t, err)
			require.Empty(t, i.ingressQueue.Len())
		})

		t.Run("with change in annotations on correct name", func(t *testing.T) {
			i := ingressClassManager{
				ingressQueue: newQueue(),
			}

			err := i.handleEvent(ingressClassUpdatedEvent{
				oldIngressClass: &slim_networkingv1.IngressClass{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: ciliumIngressClassName,
					},
				},
				newIngressClass: &slim_networkingv1.IngressClass{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: ciliumIngressClassName,
						Annotations: map[string]string{
							slim_networkingv1.AnnotationIsDefaultIngressClass: "true",
						},
					},
				},
			})
			require.NoError(t, err)
			require.Equal(t, 1, i.ingressQueue.Len())
		})
	})
}
