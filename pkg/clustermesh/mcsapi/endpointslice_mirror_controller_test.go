// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"path/filepath"
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

var mirrorTestDerivedService = derivedName(types.NamespacedName{Name: "full", Namespace: "default"})

func mirrorTestSource(name string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "full"},
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
				mcsapiv1beta1.LabelServiceName:   "full",
				discoveryv1.LabelServiceName:     mirrorTestDerivedService,
				mcsapiv1beta1.LabelSourceCluster: "cluster1",
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

func runEndpointSliceMirrorReconcile(t *testing.T, scheme *runtime.Scheme, request string, objects ...client.Object) client.Client {
	t.Helper()

	c := fake.NewClientBuilder().
		WithObjects(objects...).
		WithScheme(scheme).
		WithIndex(&discoveryv1.EndpointSlice{}, derivedEndpointSliceByLocalNameIndex, derivedEndpointSliceByLocalNameIndexFunc).
		Build()
	r := &mcsAPIEndpointSliceMirrorReconciler{
		Client:      c,
		Logger:      hivetest.Logger(t),
		clusterName: "cluster1",
	}

	result, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: request, Namespace: "default"},
	})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result, "Result should be empty")
	return c
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
				mcsapiv1beta1.LabelServiceName: "full",
				discoveryv1.LabelManagedBy:     endpointSliceLocalMCSAPIControllerName,
				localEndpointSliceLabel:        ep.Labels[localEndpointSliceLabel],
			}
		}},
		{name: "update-labels-and-owner", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Labels = map[string]string{
				mcsapiv1beta1.LabelServiceName: "full",
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			scheme := testScheme()
			objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
			source := mirrorTestSource("full-" + tt.name)
			desired := mirrorTestDesired(source, mirrorTestDerivedService+"-"+tt.name)
			objects = append(objects, source)
			if !tt.create {
				existing := desired.DeepCopy()
				if tt.mutate != nil {
					tt.mutate(existing)
				}
				objects = append(objects, existing)
			}
			c := runEndpointSliceMirrorReconcile(t, scheme, source.Name, objects...)
			requireEndpointSlice(t, c, desired)
		})
	}
}

func Test_mcsEndpointSliceMirror_LegacySourceLabel(t *testing.T) {
	scheme := testScheme()
	objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
	source := mirrorTestSource("full-legacy-label")
	desired := mirrorTestDesired(source, mirrorTestDerivedService+"-legacy-label")
	existing := desired.DeepCopy()
	existing.Annotations = nil
	objects = append(objects, source, existing)

	c := runEndpointSliceMirrorReconcile(t, scheme, source.Name, objects...)
	requireEndpointSlice(t, c, desired)
}

func Test_mcsEndpointSliceMirror_fixtures(t *testing.T) {
	for _, tt := range []struct {
		name    string
		request string
	}{
		{name: "port-filter", request: "port-filter"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("testdata/endpointslice-mirror", tt.name)
			scheme := testScheme()
			objects := k8stestutils.ReadObjectsDir(t, filepath.Join(path, "input"), scheme)
			c := runEndpointSliceMirrorReconcile(t, scheme, tt.request, objects...)

			var expected discoveryv1.EndpointSlice
			k8stestutils.ReadYAML(t, filepath.Join(path, "output/derived-endpointslice.yaml"), &expected)
			requireEndpointSlice(t, c, &expected)
		})
	}
}

func Test_mcsEndpointSliceMirror_EnsureAbsent(t *testing.T) {
	for _, tt := range []struct {
		name                string
		setupEndpointSlices func() ([]client.Object, string)
	}{
		{name: "full-delete", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("full-delete")
			derived := mirrorTestDesired(source, mirrorTestDerivedService+"-delete")
			return []client.Object{derived}, derived.Name
		}},
		{name: "full-wrong-family-delete", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("full-wrong-family-delete")
			source.AddressType = discoveryv1.AddressTypeIPv6
			derived := mirrorTestDesired(source, mirrorTestDerivedService+"-wrong-family-delete")
			return []client.Object{source, derived}, derived.Name
		}},
		{name: "full-wrong-family-ignore", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("full-wrong-family-ignore")
			source.AddressType = discoveryv1.AddressTypeIPv6
			return []client.Object{source}, mirrorTestDerivedService + "-wrong-family-ignore"
		}},
		{name: "full-not-linked-service-1", setupEndpointSlices: func() ([]client.Object, string) {
			source := mirrorTestSource("full-not-linked-service-1")
			derived := mirrorTestDesired(source, mirrorTestDerivedService+"-not-linked-service-1")
			source.Labels = nil
			return []client.Object{source, derived}, derived.Name
		}},
		{name: malformedDerivedEndpointSliceRequest(mirrorTestDerivedService + "-not-linked-service-4"), setupEndpointSlices: func() ([]client.Object, string) {
			derived := mirrorTestDesired(mirrorTestSource("full-not-linked-service-4"), mirrorTestDerivedService+"-not-linked-service-4")
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
			c := runEndpointSliceMirrorReconcile(t, scheme, tt.name, objects...)
			requireNoEndpointSlice(t, c, absent)
		})
	}
}

func Test_mcsEndpointSliceMirror_DuplicateCleanup(t *testing.T) {
	scheme := testScheme()
	objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
	source := mirrorTestSource("full-duplicate-derived")
	desired := mirrorTestDesired(source, mirrorTestDerivedService+"-duplicate-derived")
	duplicate := desired.DeepCopy()
	duplicate.Name += "-extra"
	objects = append(objects, source, desired.DeepCopy(), duplicate)

	c := runEndpointSliceMirrorReconcile(t, scheme, source.Name, objects...)
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
			expectedName: mirrorTestDerivedService + "-" + strings.Repeat("a", 223) + "-2bkdbdh4ft",
		},
		{
			name:         "service-prefixed at name limit",
			localName:    "full-" + strings.Repeat("b", 253-len(mirrorTestDerivedService)-1),
			expectedName: mirrorTestDerivedService + "-" + strings.Repeat("b", 253-len(mirrorTestDerivedService)-1),
		},
		{
			name:         "service-prefixed over name limit",
			localName:    "full-" + strings.Repeat("b", 254-len(mirrorTestDerivedService)-1),
			expectedName: mirrorTestDerivedService + "-" + strings.Repeat("b", 223) + "-5gt6bkmtcd",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scheme := testScheme()
			objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-mirror/base", scheme)
			source := mirrorTestSource(tt.localName)
			objects = append(objects, source)
			c := runEndpointSliceMirrorReconcile(t, scheme, source.Name, objects...)

			desired := mirrorTestDesired(source, tt.expectedName)
			requireEndpointSlice(t, c, desired)

			var actual discoveryv1.EndpointSlice
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(desired), &actual))
			require.Equal(t, []ctrl.Request{{NamespacedName: client.ObjectKeyFromObject(source)}}, endpointSliceMirrorRequests(&actual))

			require.NoError(t, c.Delete(t.Context(), source))
			r := &mcsAPIEndpointSliceMirrorReconciler{
				Client:      c,
				Logger:      hivetest.Logger(t),
				clusterName: "cluster1",
			}
			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(source)})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result)
			requireNoEndpointSlice(t, c, desired.Name)
		})
	}
}
