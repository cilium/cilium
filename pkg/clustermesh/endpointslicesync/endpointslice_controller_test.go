// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/pkg/annotation"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	endpointslicetypes "github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	slimdiscoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	k8stestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, discoveryv1.AddToScheme(scheme))
	return scheme
}

func remoteTestEndpointSliceSource(name string) *endpointslicetypes.ClusterEndpointSlice {
	return &endpointslicetypes.ClusterEndpointSlice{
		Cluster: "remote", Namespace: "default", Name: name,
		Labels: map[string]string{discoveryv1.LabelServiceName: "svc"},
		Endpoints: []slimdiscoveryv1.Endpoint{
			{
				Addresses: []string{"10.0.0.1"},
				Conditions: slimdiscoveryv1.EndpointConditions{
					Ready:       new(true),
					Serving:     new(true),
					Terminating: new(false),
				},
			},
			{
				Addresses: []string{"10.0.0.2"},
				Conditions: slimdiscoveryv1.EndpointConditions{
					Ready:       new(false),
					Serving:     new(true),
					Terminating: new(false),
				},
			},
		},
		Ports:       []slimdiscoveryv1.EndpointPort{{Port: new(int32(80))}},
		AddressType: slimdiscoveryv1.AddressTypeIPv4,
	}
}

func localTestEndpointSliceDesired(source *endpointslicetypes.ClusterEndpointSlice, name string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: source.Namespace,
			Labels: map[string]string{
				"test-label":                     "copied",
				discoveryv1.LabelServiceName:     "svc",
				discoveryv1.LabelManagedBy:       utils.EndpointSliceMeshControllerName,
				mcsapiv1beta1.LabelSourceCluster: source.Cluster,
			},
			Annotations: map[string]string{remoteEndpointSliceAnnotation: source.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         "v1",
				Kind:               "Service",
				Name:               "svc",
				UID:                "40108bac-8aa0-425d-903e-a1c15d896244",
				Controller:         new(true),
				BlockOwnerDeletion: new(true),
			}},
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
		AddressType: discoveryv1.AddressType(source.AddressType),
	}
}

func runEndpointSliceSyncTest(t *testing.T, source *endpointslicetypes.ClusterEndpointSlice, request types.NamespacedName, objects ...client.Object) client.Client {
	t.Helper()

	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).
		WithIndex(&discoveryv1.EndpointSlice{}, localEndpointSliceByRemoteKeyIndex, localEndpointSliceByRemoteKeyIndexFunc).
		Build()
	remoteCache := operator.NewCacheStore[*endpointslicetypes.ClusterEndpointSlice](cache.Indexers{})
	if source != nil {
		remoteCache.Update(source)
	}
	r := &endpointSliceReconciler{
		Client: c, logger: hivetest.Logger(t), cache: remoteCache,
		namespaceConfig: cmnamespace.Config{GlobalNamespacesByDefault: false},
	}

	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: request})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)
	return c
}

func requireEndpointSlice(t *testing.T, c client.Client, expected *discoveryv1.EndpointSlice) {
	t.Helper()

	var actual discoveryv1.EndpointSlice
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(expected), &actual))
	require.Empty(t, cmp.Diff(expected, &actual, cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ResourceVersion")), "EndpointSlice mismatch (-want +got)")
}

func requireNoEndpointSlice(t *testing.T, c client.Client, name string) {
	t.Helper()

	var actual discoveryv1.EndpointSlice
	err := c.Get(t.Context(), types.NamespacedName{Name: name, Namespace: "default"}, &actual)
	require.True(t, apierrors.IsNotFound(err), "EndpointSlice %s should be absent, got %v", name, err)
}

func TestEndpointSliceSyncReconcile(t *testing.T) {
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
			delete(ep.Labels, "test-label")
		}},
		{name: "update-labels-and-owner", mutate: func(ep *discoveryv1.EndpointSlice) {
			delete(ep.Labels, "test-label")
			ep.OwnerReferences = nil
		}},
		{name: "repair-service-labels", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Labels = map[string]string{
				discoveryv1.LabelManagedBy:       utils.EndpointSliceMeshControllerName,
				mcsapiv1beta1.LabelSourceCluster: ep.Labels[mcsapiv1beta1.LabelSourceCluster],
			}
		}},
		{name: "repair-service-labels-and-owner", mutate: func(ep *discoveryv1.EndpointSlice) {
			ep.Labels = map[string]string{
				discoveryv1.LabelManagedBy:       utils.EndpointSliceMeshControllerName,
				mcsapiv1beta1.LabelSourceCluster: ep.Labels[mcsapiv1beta1.LabelSourceCluster],
			}
			ep.OwnerReferences = nil
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-sync/base", testScheme(t))
			source := remoteTestEndpointSliceSource("svc-" + tt.name)
			desired := localTestEndpointSliceDesired(source, source.Name+"-"+source.Cluster)
			if !tt.create {
				existing := desired.DeepCopy()
				if tt.mutate != nil {
					tt.mutate(existing)
				}
				objects = append(objects, existing)
			}
			c := runEndpointSliceSyncTest(t, source, remoteEndpointSliceReconcileKey(source), objects...)
			requireEndpointSlice(t, c, desired)
		})
	}
}

func TestEndpointSliceSyncEnsureAbsent(t *testing.T) {
	for _, tt := range []struct {
		name                string
		setupEndpointSlices func() (*endpointslicetypes.ClusterEndpointSlice, []client.Object, string)
	}{
		{name: "svc-remote-deleted@remote", setupEndpointSlices: func() (*endpointslicetypes.ClusterEndpointSlice, []client.Object, string) {
			source := remoteTestEndpointSliceSource("svc-remote-deleted")
			local := localTestEndpointSliceDesired(source, source.Name+"-"+source.Cluster)
			return nil, []client.Object{local}, local.Name
		}},
		{name: "svc-wrong-family-delete@remote", setupEndpointSlices: func() (*endpointslicetypes.ClusterEndpointSlice, []client.Object, string) {
			source := remoteTestEndpointSliceSource("svc-wrong-family-delete")
			source.AddressType = slimdiscoveryv1.AddressTypeIPv6
			local := localTestEndpointSliceDesired(source, source.Name+"-"+source.Cluster)
			return source, []client.Object{local}, local.Name
		}},
		{name: "svc-wrong-family-ignore@remote", setupEndpointSlices: func() (*endpointslicetypes.ClusterEndpointSlice, []client.Object, string) {
			source := remoteTestEndpointSliceSource("svc-wrong-family-ignore")
			source.AddressType = slimdiscoveryv1.AddressTypeIPv6
			return source, nil, source.Name + "-" + source.Cluster
		}},
		{name: "svc-without-service-label@remote", setupEndpointSlices: func() (*endpointslicetypes.ClusterEndpointSlice, []client.Object, string) {
			source := remoteTestEndpointSliceSource("svc-without-service-label")
			local := localTestEndpointSliceDesired(source, source.Name+"-"+source.Cluster)
			source.Labels = nil
			return source, []client.Object{local}, local.Name
		}},
		{name: malformedEndpointSliceRequest("svc-missing-source-annotation-remote"), setupEndpointSlices: func() (*endpointslicetypes.ClusterEndpointSlice, []client.Object, string) {
			source := remoteTestEndpointSliceSource("svc-missing-source-annotation")
			local := localTestEndpointSliceDesired(source, source.Name+"-"+source.Cluster)
			delete(local.Annotations, remoteEndpointSliceAnnotation)
			require.Nil(t, localEndpointSliceByRemoteKeyIndexFunc(local))
			return source, []client.Object{local}, local.Name
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-sync/base", testScheme(t))
			source, endpointSlices, absent := tt.setupEndpointSlices()
			objects = append(objects, endpointSlices...)
			c := runEndpointSliceSyncTest(t, source, types.NamespacedName{Name: tt.name, Namespace: "default"}, objects...)
			requireNoEndpointSlice(t, c, absent)
		})
	}
}

func TestEndpointSliceSyncDuplicateCleanup(t *testing.T) {
	source := remoteTestEndpointSliceSource("svc-duplicate")
	desired := localTestEndpointSliceDesired(source, source.Name+"-"+source.Cluster)
	duplicate := desired.DeepCopy()
	duplicate.Name += "-extra"
	objects := k8stestutils.ReadObjectsDir(t, "testdata/endpointslice-sync/base", testScheme(t))
	objects = append(objects, desired.DeepCopy(), duplicate)
	c := runEndpointSliceSyncTest(t, source, remoteEndpointSliceReconcileKey(source), objects...)
	requireEndpointSlice(t, c, desired)
	requireNoEndpointSlice(t, c, duplicate.Name)
}

func TestShouldSyncEndpointSlice(t *testing.T) {
	for _, tt := range []struct {
		name   string
		want   bool
		mutate func(*corev1.Service)
	}{
		{name: "service-sync-disabled", mutate: func(svc *corev1.Service) {
			svc.Annotations[annotation.GlobalServiceSyncEndpointSlices] = "false"
		}},
		{name: "headless-default", want: true, mutate: func(svc *corev1.Service) {
			delete(svc.Annotations, annotation.GlobalServiceSyncEndpointSlices)
			svc.Spec.ClusterIP = corev1.ClusterIPNone
		}},
		{name: "unsupported-local-ip-family", mutate: func(svc *corev1.Service) {
			svc.Annotations[annotation.SupportedIPFamilies] = "IPv6"
		}},
		{name: "invalid-supported-families-fall-back-to-spec", want: true, mutate: func(svc *corev1.Service) {
			svc.Annotations[annotation.SupportedIPFamilies] = "invalid"
		}},
		{name: "supported-families-override-spec", want: true, mutate: func(svc *corev1.Service) {
			svc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv6Protocol}
			svc.Annotations[annotation.SupportedIPFamilies] = "IPv4"
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					annotation.GlobalService:                   "true",
					annotation.GlobalServiceSyncEndpointSlices: "true",
				}},
				Spec: corev1.ServiceSpec{IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol}},
			}
			tt.mutate(svc)
			require.Equal(t, tt.want, shouldSyncEndpointSlice(svc, slimdiscoveryv1.AddressTypeIPv4))
		})
	}
}
