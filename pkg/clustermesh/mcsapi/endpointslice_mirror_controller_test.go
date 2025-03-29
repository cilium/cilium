// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
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
				Name:         "full-keep",
				GenerateName: "full-",
				Namespace:    "default",
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
				Name:         "full-update-1",
				GenerateName: "full-",
				Namespace:    "default",
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
				Name:         "full-update-2",
				GenerateName: "full-",
				Namespace:    "default",
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
				Name:         "full-update-3",
				GenerateName: "full-",
				Namespace:    "default",
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
				Name:         "full-update-4",
				GenerateName: "full-",
				Namespace:    "default",
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
				Name:         "full-update-5",
				GenerateName: "full-",
				Namespace:    "default",
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
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            commonDerivedName + "-keep",
				GenerateName:    commonDerivedName + "-",
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
				GenerateName:    commonDerivedName + "-",
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
				GenerateName:    commonDerivedName + "-",
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
				GenerateName:    commonDerivedName + "-",
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
				Name:         commonDerivedName + "-update-4",
				GenerateName: commonDerivedName + "-",
				Namespace:    "default",
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
				Name:         commonDerivedName + "-update-5",
				GenerateName: commonDerivedName + "-",
				Namespace:    "default",
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
				Name:         commonDerivedName + "-delete",
				GenerateName: commonDerivedName + "-",
				Namespace:    "default",
				Labels:       commonLabels,
			},
			Endpoints:   commonEndpoints,
			Ports:       commonPorts,
			AddressType: discoveryv1.AddressTypeIPv4,
		},
	}
)

func getEndpointSliceFromList(name string, epsliceList discoveryv1.EndpointSliceList) *discoveryv1.EndpointSlice {
	for _, epSlice := range epsliceList.Items {
		if epSlice.Name == name {
			return &epSlice
		}
	}
	return nil
}

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

	key := types.NamespacedName{
		Name:      "full",
		Namespace: "default",
	}
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: key,
	})

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result, "Result should be empty")
	serviceReq, _ := labels.NewRequirement(mcsapiv1alpha1.LabelServiceName, selection.Equals, []string{"full"})
	controllerReq, _ := labels.NewRequirement(discoveryv1.LabelManagedBy, selection.Equals, []string{endpointSliceLocalMCSAPIControllerName})

	selector := labels.NewSelector()
	selector = selector.Add(*serviceReq)
	selector = selector.Add(*controllerReq)

	var epSliceList discoveryv1.EndpointSliceList
	err = r.List(context.Background(), &epSliceList, &client.ListOptions{LabelSelector: selector})
	require.NoError(t, err)

	require.Len(t, epSliceList.Items, 6)

	for _, suffix := range []string{"keep", "update-1", "update-2", "update-3", "update-4", "update-5"} {
		t.Run(fmt.Sprintf("Check mirrored Endpoint %s", suffix), func(t *testing.T) {
			epSlice := getEndpointSliceFromList(commonDerivedName+"-"+suffix, epSliceList)
			require.NotNil(t, epSlice)
			require.Equal(t, commonOwnerReferences, epSlice.OwnerReferences)
			require.Equal(t, commonLabels, epSlice.Labels)
			require.Len(t, epSlice.Annotations, 0)
			require.Equal(t, commonPorts, epSlice.Ports)
			require.Equal(t, commonEndpoints, epSlice.Endpoints)
			require.Equal(t, discoveryv1.AddressTypeIPv4, epSlice.AddressType)
		})
	}
}
