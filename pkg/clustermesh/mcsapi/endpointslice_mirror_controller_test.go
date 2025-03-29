// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

var (
	commonEndpoints = []discoveryv1.Endpoint{{
		Addresses: []string{"10.0.0.1", "10.0.0.2"},
	}}
	commonPorts = []discoveryv1.EndpointPort{{
		Port: ptr.To[int32](80),
	}}
	commonOwnerReferences = []metav1.OwnerReference{{
		APIVersion:         "v1",
		Kind:               "Service",
		Name:               commonDerivedName,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}}
	commonDerivedName = derivedName(types.NamespacedName{Name: "full", Namespace: "default"})
	commonLabels      = map[string]string{
		"test-label":                      "copied",
		mcsapiv1alpha1.LabelServiceName:   "full",
		discoveryv1.LabelServiceName:      commonDerivedName,
		mcsapiv1alpha1.LabelSourceCluster: "cluster1",
		discoveryv1.LabelManagedBy:        endpointSliceLocalMCSAPIControllerName,
	}

	endpointsliceMirrorFixtures = []client.Object{
		&mcsapiv1alpha1.ServiceExport{
			TypeMeta: typeMetaSvcExport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full",
				Namespace: "default",
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full",
				Namespace: "default",
			},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-keep",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update-1",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update-2",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update-3",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update-4",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update-5",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-wrong-family-delete",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv6,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-wrong-family-ignore",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv6,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "long-lorem-ipsum-dolor-sit-amet-consectetur-adipiscing",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "full",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},

		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName,
				Namespace: "default",
				Labels: map[string]string{
					"test-label": "copied",
				},
			},
			Spec: corev1.ServiceSpec{
				IPFamilies: []corev1.IPFamily{
					corev1.IPv4Protocol,
				},
				Ports: []corev1.ServicePort{{
					Port: 80,
				}},
			},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-keep",
				Namespace:       "default",
				Labels:          commonLabels,
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-update-1",
				Namespace:       "default",
				Labels:          commonLabels,
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv6,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-update-2",
				Namespace:       "default",
				Labels:          commonLabels,
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints: []discoveryv1.Endpoint{{
				Hostname: ptr.To("to-update"),
			}},
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-update-3",
				Namespace:       "default",
				Labels:          commonLabels,
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints: commonEndpoints,
			Ports: []discoveryv1.EndpointPort{{
				Port: ptr.To[int32](42),
			}},
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName + "-update-4",
				Namespace: "default",
				Labels: map[string]string{
					mcsapiv1alpha1.LabelServiceName: "full",
					discoveryv1.LabelManagedBy:      endpointSliceLocalMCSAPIControllerName,
				},
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName + "-update-5",
				Namespace: "default",
				Labels: map[string]string{
					mcsapiv1alpha1.LabelServiceName: "full",
					discoveryv1.LabelManagedBy:      endpointSliceLocalMCSAPIControllerName,
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName + "-delete",
				Namespace: "default",
				Labels:    commonLabels,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName + "-wrong-family-delete",
				Namespace: "default",
				Labels:    commonLabels,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv6,
		},
	}
)

func Test_mcsEndpointSliceMirror_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithObjects(endpointsliceMirrorFixtures...).
		WithScheme(testScheme()).
		Build()
	r := &mcsAPIEndpointSliceMirrorReconciler{
		Client:      c,
		Logger:      hivetest.Logger(t),
		clusterName: "cluster1",
	}

	for _, suffix := range []string{"keep", "", "update-1", "update-2", "update-3", "update-4", "update-5"} {
		t.Run(fmt.Sprintf("Check mirrored Endpoint %s", suffix), func(t *testing.T) {
			key := types.NamespacedName{
				Name:      "full-" + suffix,
				Namespace: "default",
			}
			if suffix == "" {
				key.Name = "full"
			}
			result, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: key,
			})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			keyDerived := types.NamespacedName{
				Name:      commonDerivedName + "-" + suffix,
				Namespace: "default",
			}
			if suffix == "" {
				keyDerived.Name = commonDerivedName
			}
			epSlice := &discoveryv1.EndpointSlice{}
			err = c.Get(t.Context(), keyDerived, epSlice)
			require.NoError(t, err)

			require.Equal(t, commonOwnerReferences, epSlice.OwnerReferences)
			require.Equal(t, commonLabels, epSlice.Labels)
			require.Equal(t, map[string]string{localEndpointSliceAnnotation: key.Name}, epSlice.Annotations)
			require.Equal(t, commonPorts, epSlice.Ports)
			require.Equal(t, commonEndpoints, epSlice.Endpoints)
			require.Equal(t, discoveryv1.AddressTypeIPv4, epSlice.AddressType)
		})
	}

	t.Run("Check very long mirrored Endpoint", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "long-lorem-ipsum-dolor-sit-amet-consectetur-adipiscing",
			Namespace: "default",
		}
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: key,
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		keyDerived := types.NamespacedName{
			Name:      commonDerivedName + "-um-dolor-sit-amet-consectetur-adipiscing",
			Namespace: "default",
		}
		epSlice := &discoveryv1.EndpointSlice{}
		err = c.Get(t.Context(), keyDerived, epSlice)
		require.NoError(t, err)
	})

	for _, suffix := range []string{"delete", "wrong-family-delete", "wrong-family-ignore"} {
		t.Run(fmt.Sprintf("Check delete Endpoint %s", suffix), func(t *testing.T) {
			keyDerived := types.NamespacedName{
				Name:      commonDerivedName + "-" + suffix,
				Namespace: "default",
			}
			result, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: keyDerived,
			})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			epSlice := &discoveryv1.EndpointSlice{}
			err = c.Get(t.Context(), keyDerived, epSlice)
			require.True(t, apierrors.IsNotFound(err), "EndpointSlice with delete suffix should be deleted")
		})
	}
}
