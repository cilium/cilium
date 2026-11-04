// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	k8stestutils "github.com/cilium/cilium/pkg/k8s/testutils"
)

var mirrorTestDerivedService = derivedName(types.NamespacedName{Name: "test", Namespace: "default"})

func mirrorTestSource(name string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "test"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{
					Ready:       new(true),
					Serving:     new(true),
					Terminating: new(false),
				},
			},
			{
				Addresses: []string{"10.0.0.2"},
				Conditions: discoveryv1.EndpointConditions{
					Ready:       new(false),
					Serving:     new(true),
					Terminating: new(false),
				},
			},
		},
		Ports:       []discoveryv1.EndpointPort{{Port: new(int32(80))}},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
}

func mirrorTestDesired(source *discoveryv1.EndpointSlice, name string) *discoveryv1.EndpointSlice {
	desired := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: source.Namespace,
			Labels: map[string]string{
				"test-label":                     "copied",
				mcsapiv1beta1.LabelServiceName:   "test",
				discoveryv1.LabelServiceName:     mirrorTestDerivedService,
				mcsapiv1beta1.LabelSourceCluster: "local",
				discoveryv1.LabelManagedBy:       endpointSliceLocalMCSAPIControllerName,
			},
			Annotations: map[string]string{localEndpointSliceNameAnnotation: source.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         "v1",
				Kind:               "Service",
				Name:               mirrorTestDerivedService,
				UID:                "40108bac-8aa0-425d-903e-a1c15d896244",
				Controller:         new(true),
				BlockOwnerDeletion: new(true),
			}},
		},
		Endpoints:   source.Endpoints,
		Ports:       source.Ports,
		AddressType: source.AddressType,
	}
	if len(source.Name) <= 63 {
		desired.Labels[localEndpointSliceLabel] = source.Name
	}
	return desired
}

func newEndpointSliceMirrorTestClient(scheme *runtime.Scheme, objects ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithObjects(objects...).
		WithScheme(scheme).
		WithIndex(&discoveryv1.EndpointSlice{}, derivedEndpointSliceByLocalNameIndex, derivedEndpointSliceByLocalNameIndexFunc).
		Build()
}

func runEndpointSliceMirrorReconcile(t *testing.T, c client.Client, request string) {
	t.Helper()

	r := &mcsAPIEndpointSliceMirrorReconciler{
		Client:      c,
		Logger:      hivetest.Logger(t),
		clusterName: "local",
	}

	result, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: request, Namespace: "default"},
	})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result, "Result should be empty")
}

func requireEndpointSlice(t *testing.T, c client.Client, expected *discoveryv1.EndpointSlice) {
	t.Helper()

	var actual discoveryv1.EndpointSlice
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(expected), &actual))
	require.Empty(t, cmp.Diff(expected, &actual, cmpIgnoreFields), "EndpointSlice mismatch (-want +got)")
}

func requireNoEndpointSlice(t *testing.T, c client.Client, name string) {
	t.Helper()

	var actual discoveryv1.EndpointSlice
	err := c.Get(t.Context(), types.NamespacedName{Name: name, Namespace: "default"}, &actual)
	require.True(t, apierrors.IsNotFound(err), "EndpointSlice %s should be absent, got %v", name, err)
}

func Test_mcsEndpointSliceMirror(t *testing.T) {
	for _, tt := range []struct {
		name   string
		create bool
		mutate func(*discoveryv1.EndpointSlice)
	}{
		{name: "create", create: true},
		{name: "keep"},
		{name: "update-address-type", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.AddressType = discoveryv1.AddressTypeIPv6
		}},
		{name: "update-endpoints", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Endpoints = []discoveryv1.Endpoint{{Hostname: new("to-update")}}
		}},
		{name: "update-ports", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Ports = []discoveryv1.EndpointPort{{Port: new(int32(42))}}
		}},
		{name: "update-labels", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Labels = map[string]string{
				mcsapiv1beta1.LabelServiceName: "test",
				discoveryv1.LabelManagedBy:     endpointSliceLocalMCSAPIControllerName,
				localEndpointSliceLabel:        ep.Labels[localEndpointSliceLabel],
			}
		}},
		{name: "update-labels-and-owner", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Labels = map[string]string{
				mcsapiv1beta1.LabelServiceName: "test",
				discoveryv1.LabelManagedBy:     endpointSliceLocalMCSAPIControllerName,
				localEndpointSliceLabel:        ep.Labels[localEndpointSliceLabel],
			}
			ep.OwnerReferences = nil
		}},
		{name: "repair-service-labels", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Labels = map[string]string{
				discoveryv1.LabelManagedBy: endpointSliceLocalMCSAPIControllerName,
				localEndpointSliceLabel:    ep.Labels[localEndpointSliceLabel],
			}
		}},
		{name: "repair-service-labels-and-owner", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Labels = map[string]string{
				discoveryv1.LabelManagedBy: endpointSliceLocalMCSAPIControllerName,
				localEndpointSliceLabel:    ep.Labels[localEndpointSliceLabel],
			}
			ep.OwnerReferences = nil
		}},
		{name: "legacy-source-label", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Annotations = nil
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scheme := testScheme()
			objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
			source := mirrorTestSource("test-" + tt.name)
			desired := mirrorTestDesired(source, mirrorTestDerivedService+"-"+tt.name)
			objects = append(objects, source)
			if !tt.create {
				existing := desired.DeepCopy()
				if tt.mutate != nil {
					tt.mutate(existing)
				}
				objects = append(objects, existing)
			}
			c := newEndpointSliceMirrorTestClient(scheme, objects...)
			runEndpointSliceMirrorReconcile(t, c, source.Name)
			requireEndpointSlice(t, c, desired)
		})
	}
}

func Test_mcsEndpointSliceMirror_EnsureAbsent(t *testing.T) {
	for _, tt := range []struct {
		name                string
		setupEndpointSlices func() ([]client.Object, string)
	}{
		{name: "test-delete", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("test-delete")
			derived := mirrorTestDesired(source, mirrorTestDerivedService+"-delete")
			return []client.Object{derived}, derived.Name
		}},
		{name: "test-wrong-family-delete", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("test-wrong-family-delete")
			source.AddressType = discoveryv1.AddressTypeIPv6
			derived := mirrorTestDesired(source, mirrorTestDerivedService+"-wrong-family-delete")
			return []client.Object{source, derived}, derived.Name
		}},
		{name: "test-wrong-family-ignore", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("test-wrong-family-ignore")
			source.AddressType = discoveryv1.AddressTypeIPv6
			return []client.Object{source}, mirrorTestDerivedService + "-wrong-family-ignore"
		}},
		{name: "test-source-without-service-label", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("test-source-without-service-label")
			derived := mirrorTestDesired(source, mirrorTestDerivedService+"-source-without-service-label")
			source.Labels = nil
			return []client.Object{source, derived}, derived.Name
		}},
		{name: malformedDerivedEndpointSliceRequest(mirrorTestDerivedService + "-without-source-reference"), setupEndpointSlices: func() ([]client.Object, string) {
			derived := mirrorTestDesired(mirrorTestSource("test-without-source-reference"), mirrorTestDerivedService+"-without-source-reference")
			derived.Labels = map[string]string{discoveryv1.LabelManagedBy: endpointSliceLocalMCSAPIControllerName}
			derived.Annotations = nil
			require.Nil(t, derivedEndpointSliceByLocalNameIndexFunc(derived))
			return []client.Object{derived}, derived.Name
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scheme := testScheme()
			objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
			configured, absent := tt.setupEndpointSlices()
			objects = append(objects, configured...)
			c := newEndpointSliceMirrorTestClient(scheme, objects...)
			runEndpointSliceMirrorReconcile(t, c, tt.name)
			requireNoEndpointSlice(t, c, absent)
		})
	}
}

func Test_mcsEndpointSliceMirror_DuplicateCleanup(t *testing.T) {
	scheme := testScheme()
	objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
	source := mirrorTestSource("test-duplicate-derived")
	desired := mirrorTestDesired(source, mirrorTestDerivedService+"-duplicate-derived")
	duplicate := desired.DeepCopy()
	duplicate.Name += "-extra"
	objects = append(objects, source, desired.DeepCopy(), duplicate)

	c := newEndpointSliceMirrorTestClient(scheme, objects...)
	runEndpointSliceMirrorReconcile(t, c, source.Name)
	requireEndpointSlice(t, c, desired)
	requireNoEndpointSlice(t, c, duplicate.Name)
}

func Test_mcsEndpointSliceMirror_NameBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name         string
		localName    string
		expectedName string
	}{
		{
			name:         "long suffix preserved",
			localName:    "long-lorem-ipsum-dolor-sit-amet-consectetur-adipiscing",
			expectedName: mirrorTestDerivedService + "-long-lorem-ipsum-dolor-sit-amet-consectetur-adipiscing",
		},
		{
			name:         "at name limit",
			localName:    strings.Repeat("a", 253-len(mirrorTestDerivedService)-1),
			expectedName: mirrorTestDerivedService + "-" + strings.Repeat("a", 253-len(mirrorTestDerivedService)-1),
		},
		{
			name:         "over name limit",
			localName:    strings.Repeat("a", 254-len(mirrorTestDerivedService)-1),
			expectedName: mirrorTestDerivedService + "-" + strings.Repeat("a", 223) + "-bg545tk8c8",
		},
		{
			name:         "service-prefixed at name limit",
			localName:    "test-" + strings.Repeat("b", 253-len(mirrorTestDerivedService)-1),
			expectedName: mirrorTestDerivedService + "-" + strings.Repeat("b", 253-len(mirrorTestDerivedService)-1),
		},
		{
			name:         "service-prefixed over name limit",
			localName:    "test-" + strings.Repeat("b", 254-len(mirrorTestDerivedService)-1),
			expectedName: mirrorTestDerivedService + "-" + strings.Repeat("b", 223) + "-tb97gd92b7",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scheme := testScheme()
			objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
			source := mirrorTestSource(tt.localName)
			objects = append(objects, source)
			c := newEndpointSliceMirrorTestClient(scheme, objects...)
			runEndpointSliceMirrorReconcile(t, c, source.Name)

			desired := mirrorTestDesired(source, tt.expectedName)
			requireEndpointSlice(t, c, desired)

			var actual discoveryv1.EndpointSlice
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(desired), &actual))
			require.Equal(t, []ctrl.Request{{NamespacedName: client.ObjectKeyFromObject(source)}}, endpointSliceMirrorRequests(&actual))

			require.NoError(t, c.Delete(t.Context(), source))
			runEndpointSliceMirrorReconcile(t, c, source.Name)
			requireNoEndpointSlice(t, c, desired.Name)
		})
	}
}
