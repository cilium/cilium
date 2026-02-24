// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"fmt"
	"maps"
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

func getExpectedDerivedLabels(localEpSliceName string) map[string]string {
	labels := maps.Clone(commonLabels)
	labels[localEndpointSliceLabel] = localEpSliceName
	return labels
}

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
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-not-linked-service-1",
				Namespace: "default",
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-not-linked-service-2",
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
				Name:      "full-not-linked-service-3",
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
				Name:      "full-not-linked-service-4",
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
				Labels:          getExpectedDerivedLabels("full-keep"),
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
				Labels:          getExpectedDerivedLabels("full-update-1"),
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
				Labels:          getExpectedDerivedLabels("full-update-2"),
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
				Labels:          getExpectedDerivedLabels("full-update-3"),
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
					localEndpointSliceLabel:         "full-update-4",
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
					localEndpointSliceLabel:         "full-update-5",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-delete",
				Namespace:       "default",
				Labels:          getExpectedDerivedLabels("full-delete"),
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-wrong-family-delete",
				Namespace:       "default",
				Labels:          getExpectedDerivedLabels("full-wrong-family-delete"),
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv6,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-not-linked-service-1",
				Namespace:       "default",
				Labels:          getExpectedDerivedLabels("full-not-linked-service-1"),
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName + "-not-linked-service-2",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelManagedBy: endpointSliceLocalMCSAPIControllerName,
					localEndpointSliceLabel:    "full-not-linked-service-2",
				},
				OwnerReferences: commonOwnerReferences,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName + "-not-linked-service-3",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelManagedBy: endpointSliceLocalMCSAPIControllerName,
					localEndpointSliceLabel:    "full-not-linked-service-3",
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      commonDerivedName + "-not-linked-service-4",
				Namespace: "default",
				Labels: map[string]string{
					discoveryv1.LabelManagedBy: endpointSliceLocalMCSAPIControllerName,
				},
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
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

	for _, tt := range []struct {
		suffix                string
		derivedReconciliation bool
	}{
		{suffix: "keep"},
		{suffix: ""},
		{suffix: "update-1"},
		{suffix: "update-2"},
		{suffix: "update-3"},
		{suffix: "update-4"},
		{suffix: "update-5"},
		{
			suffix:                "not-linked-service-2",
			derivedReconciliation: true,
		},
		{
			suffix:                "not-linked-service-3",
			derivedReconciliation: true,
		},
	} {
		t.Run(fmt.Sprintf("Check mirrored Endpoint %s", tt.suffix), func(t *testing.T) {
			fullSuffix := "-" + tt.suffix
			if tt.suffix == "" {
				fullSuffix = ""
			}

			key := types.NamespacedName{
				Name:      "full" + fullSuffix,
				Namespace: "default",
			}
			if tt.derivedReconciliation {
				key.Name = commonDerivedName + fullSuffix
			}
			result, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: key,
			})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			keyDerived := types.NamespacedName{
				Name:      commonDerivedName + "-" + tt.suffix,
				Namespace: "default",
			}
			if tt.suffix == "" {
				keyDerived.Name = commonDerivedName
			}
			epSlice := &discoveryv1.EndpointSlice{}
			err = c.Get(t.Context(), keyDerived, epSlice)
			require.NoError(t, err)

			require.Equal(t, commonOwnerReferences, epSlice.OwnerReferences)
			require.Equal(t, getExpectedDerivedLabels("full"+fullSuffix), epSlice.Labels)
			require.Empty(t, epSlice.Annotations)
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

	for _, tt := range []struct {
		suffix              string
		localReconciliation bool
	}{
		{suffix: "delete"},
		{suffix: "wrong-family-delete"},
		{suffix: "wrong-family-ignore"},
		{
			suffix:              "not-linked-service-1",
			localReconciliation: true,
		},
		{suffix: "not-linked-service-4"},
	} {
		t.Run(fmt.Sprintf("Check delete Endpoint %s", tt.suffix), func(t *testing.T) {
			keyDerived := types.NamespacedName{
				Name:      commonDerivedName + "-" + tt.suffix,
				Namespace: "default",
			}
			keyReconcile := keyDerived
			if tt.localReconciliation {
				keyReconcile.Name = "full-" + tt.suffix
			}
			result, err := r.Reconcile(t.Context(), ctrl.Request{
				NamespacedName: keyReconcile,
			})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			epSlice := &discoveryv1.EndpointSlice{}
			err = c.Get(t.Context(), keyDerived, epSlice)
			require.True(t, apierrors.IsNotFound(err), "EndpointSlice should be deleted")
		})
	}
}
