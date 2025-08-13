// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8sApiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	mcsapicontrollers "sigs.k8s.io/mcs-api/controllers"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	localClusterName  = "local"
	remoteClusterName = "remote"
)

var (
	olderTime = metav1.NewTime(time.Now().AddDate(0, 0, -1))
	nowTime   = metav1.Now()
	newerTime = metav1.NewTime(time.Now().AddDate(0, 0, 1))
)

func getServiceImport(client client.Client, key types.NamespacedName) (*mcsapiv1alpha1.ServiceImport, error) {
	svcImport := mcsapiv1alpha1.ServiceImport{}
	err := client.Get(context.Background(), key, &svcImport)
	if err != nil {
		return nil, err
	}
	return &svcImport, nil
}

func getServiceExport(client client.Client, key types.NamespacedName) (*mcsapiv1alpha1.ServiceExport, error) {
	svcExport := mcsapiv1alpha1.ServiceExport{}
	err := client.Get(context.Background(), key, &svcExport)
	if err != nil {
		return nil, err
	}
	return &svcExport, nil
}

func Test_mcsServiceImport_Reconcile(t *testing.T) {
	var (
		svcImportTestFixtures = []client.Object{
			&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "local-only",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "local-only",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
					Ports: []corev1.ServicePort{{
						Port: 8000,
					}},
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "delete-local",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "delete-local",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "basic",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
				Spec: mcsapiv1alpha1.ServiceExportSpec{
					ExportedAnnotations: map[string]string{
						"service.cilium.io/global-sync-endpoint-slices": "true",
					},
					ExportedLabels: map[string]string{
						"my-label": "test",
					},
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
					Ports: []corev1.ServicePort{
						{
							Name: "named",
							Port: 80,
						}, {
							Port: 4242,
						},
					},
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "svcimport-exist",
					Namespace:         "default",
					CreationTimestamp: olderTime,
				},
				Spec: mcsapiv1alpha1.ServiceExportSpec{
					ExportedLabels:      map[string]string{"exported-label": ""},
					ExportedAnnotations: map[string]string{"exported-annotation": ""},
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svcimport-exist",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
					Ports: []corev1.ServicePort{{
						Port: 8000,
					}},
				},
			},
			&mcsapiv1alpha1.ServiceImport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svcimport-exist",
					Namespace: "default",
					Annotations: map[string]string{
						mcsapicontrollers.DerivedServiceAnnotation: "",
						"unknown-annotation":                       "",
					},
					Labels: map[string]string{
						"unknown-label": "",
					},
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-type-remove",
					Namespace:         "default",
					CreationTimestamp: olderTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-type-remove",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-type",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-type",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-port-name",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-port-name",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
					Ports: []corev1.ServicePort{{
						Port: 4242,
					}},
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-port-appprotocol",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-port-appprotocol",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
					Ports: []corev1.ServicePort{{
						Port: 4242,
					}},
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-duplicated-port-name",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-duplicated-port-name",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
					Ports: []corev1.ServicePort{{
						Name: "myport",
						Port: 4242,
					}},
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-session-affinity",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-session-affinity",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-session-affinity-config",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-session-affinity-config",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					SessionAffinity: corev1.ServiceAffinityClientIP,
					SessionAffinityConfig: &corev1.SessionAffinityConfig{
						ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: ptr.To[int32](4242)},
					},
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-annotations",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
				Spec: mcsapiv1alpha1.ServiceExportSpec{
					ExportedAnnotations: map[string]string{
						"service.cilium.io/global-sync-endpoint-slices": "true",
					},
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-annotations",
					Namespace: "default",
				},
			},

			&mcsapiv1alpha1.ServiceExport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "conflict-labels",
					Namespace:         "default",
					CreationTimestamp: nowTime,
				},
				Spec: mcsapiv1alpha1.ServiceExportSpec{
					ExportedLabels: map[string]string{
						"my-label": "test",
					},
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-labels",
					Namespace: "default",
				},
			},
		}
		remoteSvcImportTestFixtures = []*mcsapitypes.MCSAPIServiceSpec{
			{
				Cluster:                 remoteClusterName,
				Name:                    "remote-only",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "delete-remote",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "unknown-ns",
				Namespace:               "unknown",
				ExportCreationTimestamp: olderTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			{
				Cluster:   remoteClusterName,
				Name:      "basic",
				Namespace: "default",
				Annotations: map[string]string{
					"service.cilium.io/global-sync-endpoint-slices": "true",
				},
				Labels: map[string]string{
					"my-label": "test",
				},
				ExportCreationTimestamp: olderTime,
				Ports: []mcsapiv1alpha1.ServicePort{
					{
						Name: "named",
						Port: 80,
					}, {
						Port: 4242,
					},
				},
				Type:            mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity: corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "multiple-clusters",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "conflict-type-remove",
				Namespace:               "default",
				ExportCreationTimestamp: nowTime,
				Type:                    mcsapiv1alpha1.Headless,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "conflict-type",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Type:                    mcsapiv1alpha1.Headless,
				SessionAffinity:         corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "conflict-port-name",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Ports: []mcsapiv1alpha1.ServicePort{
					{Name: "remote", Port: 4242},
				},
				Type:            mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity: corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "conflict-port-appprotocol",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Ports: []mcsapiv1alpha1.ServicePort{
					{Port: 4242, AppProtocol: ptr.To("something-else")},
				},
				Type:            mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity: corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "conflict-duplicated-port-name",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Ports: []mcsapiv1alpha1.ServicePort{
					{Name: "myport", Port: 4243},
				},
				Type:            mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity: corev1.ServiceAffinityNone,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "conflict-session-affinity",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Ports:                   []mcsapiv1alpha1.ServicePort{},
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityClientIP,
			},
			{
				Cluster:                 remoteClusterName,
				Name:                    "conflict-session-affinity-config",
				Namespace:               "default",
				ExportCreationTimestamp: olderTime,
				Ports:                   []mcsapiv1alpha1.ServicePort{},
				Type:                    mcsapiv1alpha1.ClusterSetIP,
				SessionAffinity:         corev1.ServiceAffinityClientIP,
				SessionAffinityConfig: &corev1.SessionAffinityConfig{
					ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: ptr.To[int32](42)},
				},
			},
			{
				Cluster:   remoteClusterName,
				Name:      "conflict-annotations",
				Namespace: "default",
				Annotations: map[string]string{
					"service.cilium.io/global-sync-endpoint-slices": "true",
					"service.cilium.io/lb-l7":                       "true",
				},
				ExportCreationTimestamp: olderTime,
				Ports:                   []mcsapiv1alpha1.ServicePort{},
				Type:                    mcsapiv1alpha1.ClusterSetIP,
			},
			{
				Cluster:   remoteClusterName,
				Name:      "conflict-labels",
				Namespace: "default",
				Labels: map[string]string{
					"my-label":  "test",
					"my-label2": "test",
				},

				ExportCreationTimestamp: olderTime,
				Ports:                   []mcsapiv1alpha1.ServicePort{},
				Type:                    mcsapiv1alpha1.ClusterSetIP,
			},
		}
	)

	c := fake.NewClientBuilder().
		WithObjects(svcImportTestFixtures...).
		WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
		WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
		WithScheme(testScheme()).
		Build()
	globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}
	for _, svcExport := range remoteSvcImportTestFixtures {
		globalServiceExports.OnUpdate(svcExport)
	}

	r := &mcsAPIServiceImportReconciler{
		Client:                     c,
		Logger:                     hivetest.Logger(t),
		cluster:                    localClusterName,
		globalServiceExports:       globalServiceExports,
		remoteClusterServiceSource: remoteClusterServiceSource,
		annotatedNamespaces:        sets.New[string](),
		globalNamespaces:           sets.New[string](),
		filteringActive:            false,
		defaultGlobalNamespace:     false, // Test with default to false
	}

	t.Run("Service import creation with local-only", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "local-only",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)
		require.Equal(t, mcsapiv1alpha1.ServiceImportSpec{
			Ports: []mcsapiv1alpha1.ServicePort{{
				Port: 8000,
			}},
			Type:                  mcsapiv1alpha1.ClusterSetIP,
			SessionAffinity:       corev1.ServiceAffinityNone,
			SessionAffinityConfig: nil,
		}, svcImport.Spec)
		require.Len(t, svcImport.Status.Clusters, 1)

		svcExport, err := getServiceExport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcExport)
		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, conditionTypeReady))
		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportValid))
		require.Nil(t, meta.FindStatusCondition(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportConflict))
	})

	t.Run("Service import creation with remote-only", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "remote-only",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)
		require.Len(t, svcImport.Status.Clusters, 1)
		require.Equal(t, remoteClusterName, svcImport.Status.Clusters[0].Cluster)
	})

	t.Run("Service import creation with unknown ns", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "unknown-ns",
			Namespace: "unknown",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.True(t, k8sApiErrors.IsNotFound(err), "Service import shouldn't be created")
		require.Nil(t, svcImport)
	})

	t.Run("Service import creation with unknown name", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "unknown",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.True(t, k8sApiErrors.IsNotFound(err), "Service import shouldn't be created")
		require.Nil(t, svcImport)
	})

	t.Run("Basic service import sync", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "basic",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)
		require.Len(t, svcImport.Spec.Ports, 2)
		require.ElementsMatch(t, svcImport.Spec.Ports, []mcsapiv1alpha1.ServicePort{
			{
				Port: 4242,
			}, {
				Name: "named",
				Port: 80,
			},
		})
		require.Len(t, svcImport.Status.Clusters, 2)
		require.ElementsMatch(t, svcImport.Status.Clusters, []mcsapiv1alpha1.ClusterStatus{
			{Cluster: localClusterName},
			{Cluster: remoteClusterName},
		})

		svcExport, err := getServiceExport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcExport)
		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, conditionTypeReady))
		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportValid))
		require.Nil(t, meta.FindStatusCondition(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportConflict))
	})

	t.Run("Delete local service test", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "delete-local",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)

		svcExport, err := getServiceExport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcExport)

		require.NoError(t, c.Delete(context.Background(), svcExport))

		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err = getServiceImport(c, key)
		require.True(t, k8sApiErrors.IsNotFound(err), "Service import shouldn't be created")
		require.Nil(t, svcImport)
	})

	t.Run("Delete remote service test", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "delete-remote",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)

		remoteSvcExport := globalServiceExports.GetServiceExportByCluster(key)[remoteClusterName]
		globalServiceExports.OnDelete(remoteSvcExport)

		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err = getServiceImport(c, key)
		require.True(t, k8sApiErrors.IsNotFound(err), "Service import shouldn't be created")
		require.Nil(t, svcImport)
	})

	t.Run("Check ServiceImport status on multiple remote clusters", func(t *testing.T) {
		otherClusterName := "other"
		key := types.NamespacedName{
			Name:      "multiple-clusters",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)
		require.Len(t, svcImport.Status.Clusters, 1)
		require.Equal(t, remoteClusterName, svcImport.Status.Clusters[0].Cluster)

		globalServiceExports.OnUpdate(&mcsapitypes.MCSAPIServiceSpec{
			Cluster:                 otherClusterName,
			Name:                    "multiple-clusters",
			Namespace:               "default",
			ExportCreationTimestamp: olderTime,
			Type:                    mcsapiv1alpha1.ClusterSetIP,
			SessionAffinity:         corev1.ServiceAffinityNone,
		})

		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err = getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)
		require.Len(t, svcImport.Status.Clusters, 2)
		require.ElementsMatch(t, svcImport.Status.Clusters, []mcsapiv1alpha1.ClusterStatus{
			{
				Cluster: remoteClusterName,
			}, {
				Cluster: otherClusterName,
			},
		})
	})

	t.Run("Check annotation and labels sync on an existing service import", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "svcimport-exist",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)

		require.True(t, maps.Equal(svcImport.Labels, map[string]string{
			"exported-label": "",
		}))
		fmt.Println(svcImport.Annotations)
		require.True(t, maps.Equal(svcImport.Annotations, map[string]string{
			mcsapicontrollers.DerivedServiceAnnotation: "",
			"exported-annotation":                      "",
		}))
	})

	t.Run("Check conflict removal", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "conflict-type-remove",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err := getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)
		require.Equal(t, mcsapiv1alpha1.ClusterSetIP, svcImport.Spec.Type)

		svcExport, err := getServiceExport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcExport)

		require.True(t, meta.IsStatusConditionFalse(svcExport.Status.Conditions, conditionTypeReady))
		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportValid))
		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportConflict))

		globalServiceExports.OnUpdate(&mcsapitypes.MCSAPIServiceSpec{
			Cluster:                 remoteClusterName,
			Name:                    "conflict-type-remove",
			Namespace:               "default",
			ExportCreationTimestamp: nowTime,
			Type:                    mcsapiv1alpha1.ClusterSetIP,
			SessionAffinity:         corev1.ServiceAffinityNone,
		})

		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		svcImport, err = getServiceImport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcImport)
		require.Equal(t, mcsapiv1alpha1.ClusterSetIP, svcImport.Spec.Type)

		svcExport, err = getServiceExport(c, key)
		require.NoError(t, err)
		require.NotNil(t, svcExport)

		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, conditionTypeReady))
		require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportValid))
		require.Nil(t, meta.FindStatusCondition(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportConflict))
	})

	conflictTests := []struct {
		name                 string
		remoteSvcImportValid func(*mcsapiv1alpha1.ServiceImport) bool
		localSvcImportValid  func(*mcsapiv1alpha1.ServiceImport) bool
		assertMsgInclude     string
	}{
		{
			name: "conflict-type",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return svcImport.Spec.Type == mcsapiv1alpha1.Headless
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return svcImport.Spec.Type == mcsapiv1alpha1.ClusterSetIP
			},
			assertMsgInclude: "1/2 clusters disagree",
		},
		{
			name: "conflict-port-name",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return len(svcImport.Spec.Ports) == 1 && svcImport.Spec.Ports[0].Name == "remote"
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return len(svcImport.Spec.Ports) == 1 && svcImport.Spec.Ports[0].Name == ""
			},
		},
		{
			name: "conflict-port-appprotocol",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return len(svcImport.Spec.Ports) == 1 && ptr.Deref(svcImport.Spec.Ports[0].AppProtocol, "") == "something-else"
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return len(svcImport.Spec.Ports) == 1 && ptr.Deref(svcImport.Spec.Ports[0].AppProtocol, "") == ""
			},
		},
		{
			name: "conflict-duplicated-port-name",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return len(svcImport.Spec.Ports) == 1 && svcImport.Spec.Ports[0].Port == 4243
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return len(svcImport.Spec.Ports) == 1 && svcImport.Spec.Ports[0].Port == 4242
			},
		},
		{
			name: "conflict-session-affinity",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return svcImport.Spec.SessionAffinity == corev1.ServiceAffinityClientIP
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return svcImport.Spec.SessionAffinity == corev1.ServiceAffinityNone
			},
		},
		{
			name: "conflict-session-affinity-config",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return *svcImport.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds == 42
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return *svcImport.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds == 4242
			},
		},
		{
			name: "conflict-annotations",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return maps.Equal(svcImport.Annotations, map[string]string{
					"service.cilium.io/global-sync-endpoint-slices": "true",
					"service.cilium.io/lb-l7":                       "true",
				})
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return maps.Equal(svcImport.Annotations, map[string]string{
					"service.cilium.io/global-sync-endpoint-slices": "true",
				})
			},
		},
		{
			name: "conflict-labels",
			remoteSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return maps.Equal(svcImport.Labels, map[string]string{
					"my-label":  "test",
					"my-label2": "test",
				})
			},
			localSvcImportValid: func(svcImport *mcsapiv1alpha1.ServiceImport) bool {
				return maps.Equal(svcImport.Labels, map[string]string{
					"my-label": "test",
				})
			},
		},
	}

	for _, conflictTest := range conflictTests {
		t.Run("Conflict test "+conflictTest.name+" with remote conflict", func(t *testing.T) {
			key := types.NamespacedName{
				Name:      conflictTest.name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			svcImport, err := getServiceImport(c, key)
			require.NoError(t, err)
			require.NotNil(t, svcImport)
			require.True(t, conflictTest.remoteSvcImportValid(svcImport))

			svcExport, err := getServiceExport(c, key)
			require.NoError(t, err)
			require.NotNil(t, svcExport)

			require.True(t, meta.IsStatusConditionFalse(svcExport.Status.Conditions, conditionTypeReady))
			require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportValid))
			require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportConflict))

			if conflictTest.assertMsgInclude != "" {
				condition := meta.FindStatusCondition(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportConflict)
				require.NotNil(t, condition)
				require.Contains(t, condition.Message, conflictTest.assertMsgInclude)
			}
		})
	}

	for _, remoteFixture := range remoteSvcImportTestFixtures {
		remoteFixture.ExportCreationTimestamp = newerTime
	}

	for _, conflictTest := range conflictTests {
		t.Run("Conflict test "+conflictTest.name+" with local precedence", func(t *testing.T) {
			key := types.NamespacedName{
				Name:      conflictTest.name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			svcImport, err := getServiceImport(c, key)
			require.NoError(t, err)
			require.NotNil(t, svcImport)
			require.True(t, conflictTest.localSvcImportValid(svcImport))

			svcExport, err := getServiceExport(c, key)
			require.NoError(t, err)
			require.NotNil(t, svcExport)

			require.True(t, meta.IsStatusConditionFalse(svcExport.Status.Conditions, conditionTypeReady))
			require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportValid))
			require.True(t, meta.IsStatusConditionTrue(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportConflict))
		})
	}
}

func Test_mcsServiceImport_NamespaceFiltering(t *testing.T) {
	globalNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-ns",
			Annotations: map[string]string{
				"clustermesh.cilium.io/global": "true",
			},
		},
	}
	localNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "local-ns",
			Annotations: map[string]string{
				"clustermesh.cilium.io/global": "false",
			},
		},
	}
	defaultNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-ns",
		},
	}

	globalService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "global-service",
			Namespace: "global-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8080}},
		},
	}
	localService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "local-service",
			Namespace: "local-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 9090}},
		},
	}
	defaultService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-service",
			Namespace: "default-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 7070}},
		},
	}

	globalServiceExport := &mcsapiv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "global-service",
			Namespace:         "global-ns",
			CreationTimestamp: nowTime,
		},
	}
	localServiceExport := &mcsapiv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "local-service",
			Namespace:         "local-ns",
			CreationTimestamp: nowTime,
		},
	}
	defaultServiceExport := &mcsapiv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "default-service",
			Namespace:         "default-ns",
			CreationTimestamp: nowTime,
		},
	}

	fixtures := []client.Object{
		globalNS, localNS, defaultNS,
		globalService, localService, defaultService,
		globalServiceExport, localServiceExport, defaultServiceExport,
	}

	globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}

	t.Run("Test with defaultGlobalNamespace=false", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithObjects(fixtures...).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
			WithScheme(testScheme()).
			Build()

		r := &mcsAPIServiceImportReconciler{
			Client:                     c,
			Logger:                     hivetest.Logger(t),
			cluster:                    localClusterName,
			globalServiceExports:       globalServiceExports,
			remoteClusterServiceSource: remoteClusterServiceSource,
			annotatedNamespaces:        sets.New[string](),
			globalNamespaces:           sets.New[string](),
			filteringActive:            false,
			defaultGlobalNamespace:     false,
		}

		// Simulate namespace state updates
		r.updateNamespaceState(context.Background(), globalNS)
		r.updateNamespaceState(context.Background(), localNS)

		// Global namespace: should create ServiceImport
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "global-service", Namespace: "global-ns"},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		svcImport, err := getServiceImport(c, types.NamespacedName{Name: "global-service", Namespace: "global-ns"})
		require.NoError(t, err)
		require.NotNil(t, svcImport)

		// Local namespace: should NOT create ServiceImport
		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "local-service", Namespace: "local-ns"},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		svcImport, err = getServiceImport(c, types.NamespacedName{Name: "local-service", Namespace: "local-ns"})
		require.True(t, k8sApiErrors.IsNotFound(err))
		require.Nil(t, svcImport)

		// Default namespace with defaultGlobalNamespace=false: should NOT create ServiceImport
		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "default-service", Namespace: "default-ns"},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		svcImport, err = getServiceImport(c, types.NamespacedName{Name: "default-service", Namespace: "default-ns"})
		require.True(t, k8sApiErrors.IsNotFound(err))
		require.Nil(t, svcImport)
	})

	t.Run("Test with defaultGlobalNamespace=true", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithObjects(fixtures...).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
			WithScheme(testScheme()).
			Build()

		r := &mcsAPIServiceImportReconciler{
			Client:                     c,
			Logger:                     hivetest.Logger(t),
			cluster:                    localClusterName,
			globalServiceExports:       globalServiceExports,
			remoteClusterServiceSource: remoteClusterServiceSource,
			annotatedNamespaces:        sets.New[string](),
			globalNamespaces:           sets.New[string](),
			filteringActive:            false,
			defaultGlobalNamespace:     true,
		}

		// Simulate namespace state updates
		r.updateNamespaceState(context.Background(), globalNS)
		r.updateNamespaceState(context.Background(), localNS)

		// Global namespace: should create ServiceImport
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "global-service", Namespace: "global-ns"},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		svcImport, err := getServiceImport(c, types.NamespacedName{Name: "global-service", Namespace: "global-ns"})
		require.NoError(t, err)
		require.NotNil(t, svcImport)

		// Local namespace: should NOT create ServiceImport
		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "local-service", Namespace: "local-ns"},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		svcImport, err = getServiceImport(c, types.NamespacedName{Name: "local-service", Namespace: "local-ns"})
		require.True(t, k8sApiErrors.IsNotFound(err))
		require.Nil(t, svcImport)

		// Default namespace with defaultGlobalNamespace=true: should create ServiceImport
		result, err = r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "default-service", Namespace: "default-ns"},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		svcImport, err = getServiceImport(c, types.NamespacedName{Name: "default-service", Namespace: "default-ns"})
		require.NoError(t, err)
		require.NotNil(t, svcImport)
	})

	t.Run("Test backwards compatibility - no annotations", func(t *testing.T) {
		// Remove annotation from namespaces to test backwards compatibility
		globalNSNoAnnotation := globalNS.DeepCopy()
		globalNSNoAnnotation.Annotations = nil
		localNSNoAnnotation := localNS.DeepCopy()
		localNSNoAnnotation.Annotations = nil

		fixtures := []client.Object{
			globalNSNoAnnotation, localNSNoAnnotation, defaultNS,
			globalService, localService, defaultService,
			globalServiceExport, localServiceExport, defaultServiceExport,
		}

		c := fake.NewClientBuilder().
			WithObjects(fixtures...).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
			WithScheme(testScheme()).
			Build()

		r := &mcsAPIServiceImportReconciler{
			Client:                     c,
			Logger:                     hivetest.Logger(t),
			cluster:                    localClusterName,
			globalServiceExports:       globalServiceExports,
			remoteClusterServiceSource: remoteClusterServiceSource,
			annotatedNamespaces:        sets.New[string](),
			globalNamespaces:           sets.New[string](),
			filteringActive:            false,
			defaultGlobalNamespace:     false, // This should not matter when no annotations exist
		}

		// No namespace updates - should remain in backwards compatibility mode

		// All namespaces should behave as global (backwards compatibility)
		for _, ns := range []string{"global-ns", "local-ns", "default-ns"} {
			for _, svc := range []string{"global-service", "local-service", "default-service"} {
				if (ns == "global-ns" && svc != "global-service") ||
					(ns == "local-ns" && svc != "local-service") ||
					(ns == "default-ns" && svc != "default-service") {
					continue
				}

				result, err := r.Reconcile(context.Background(), ctrl.Request{
					NamespacedName: types.NamespacedName{Name: svc, Namespace: ns},
				})
				require.NoError(t, err)
				require.Equal(t, ctrl.Result{}, result)

				svcImport, err := getServiceImport(c, types.NamespacedName{Name: svc, Namespace: ns})
				require.NoError(t, err, "ServiceImport should be created in backwards compatibility mode for %s/%s", ns, svc)
				require.NotNil(t, svcImport)
			}
		}
	})

	t.Run("Test existing ServiceImport deletion when namespace becomes local", func(t *testing.T) {
		// Create a ServiceImport that should be deleted when namespace becomes local
		existingServiceImport := &mcsapiv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-service",
				Namespace: "test-ns",
			},
		}

		testNS := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ns",
				Annotations: map[string]string{
					"clustermesh.cilium.io/global": "false", // This namespace is local
				},
			},
		}

		testService := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "existing-service",
				Namespace: "test-ns",
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 6060}},
			},
		}

		testServiceExport := &mcsapiv1alpha1.ServiceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "existing-service",
				Namespace:         "test-ns",
				CreationTimestamp: nowTime,
			},
		}

		fixtures := []client.Object{
			testNS, testService, testServiceExport, existingServiceImport,
		}

		c := fake.NewClientBuilder().
			WithObjects(fixtures...).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
			WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
			WithScheme(testScheme()).
			Build()

		r := &mcsAPIServiceImportReconciler{
			Client:                     c,
			Logger:                     hivetest.Logger(t),
			cluster:                    localClusterName,
			globalServiceExports:       globalServiceExports,
			remoteClusterServiceSource: remoteClusterServiceSource,
			annotatedNamespaces:        sets.New[string](),
			globalNamespaces:           sets.New[string](),
			filteringActive:            false,
			defaultGlobalNamespace:     false,
		}

		// Update namespace state to make it local
		r.updateNamespaceState(context.Background(), testNS)

		// Verify the ServiceImport exists initially
		svcImport, err := getServiceImport(c, types.NamespacedName{Name: "existing-service", Namespace: "test-ns"})
		require.NoError(t, err)
		require.NotNil(t, svcImport)

		// Reconcile - should delete the ServiceImport because namespace is local
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "existing-service", Namespace: "test-ns"},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		// Verify the ServiceImport is deleted
		svcImport, err = getServiceImport(c, types.NamespacedName{Name: "existing-service", Namespace: "test-ns"})
		require.True(t, k8sApiErrors.IsNotFound(err))
		require.Nil(t, svcImport)
	})
}

func Test_mcsServiceImport_OperatorIntegration(t *testing.T) {
	// Test that the defaultGlobalNamespace flag from operator config is properly used
	globalNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-ns",
			Annotations: map[string]string{
				"clustermesh.cilium.io/global": "true",
			},
		},
	}
	defaultNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-ns",
		},
	}

	defaultService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-service",
			Namespace: "default-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 7070}},
		},
	}

	defaultServiceExport := &mcsapiv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "default-service",
			Namespace:         "default-ns",
			CreationTimestamp: nowTime,
		},
	}

	fixtures := []client.Object{
		globalNS, defaultNS,
		defaultService,
		defaultServiceExport,
	}

	globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}

	testCases := []struct {
		name                       string
		defaultGlobalNamespace     bool
		expectServiceImportCreated bool
		description                string
	}{
		{
			name:                       "operator flag false - non-annotated namespace should be local",
			defaultGlobalNamespace:     false,
			expectServiceImportCreated: false,
			description:                "When operator sets defaultGlobalNamespace=false, non-annotated namespaces should be local",
		},
		{
			name:                       "operator flag true - non-annotated namespace should be global",
			defaultGlobalNamespace:     true,
			expectServiceImportCreated: true,
			description:                "When operator sets defaultGlobalNamespace=true, non-annotated namespaces should be global",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().
				WithObjects(fixtures...).
				WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
				WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
				WithScheme(testScheme()).
				Build()

			// Create reconciler using constructor directly to test operator integration
			r := &mcsAPIServiceImportReconciler{
				Client:                     c,
				Logger:                     hivetest.Logger(t),
				cluster:                    localClusterName,
				globalServiceExports:       globalServiceExports,
				remoteClusterServiceSource: remoteClusterServiceSource,
				annotatedNamespaces:        sets.New[string](),
				globalNamespaces:           sets.New[string](),
				filteringActive:            false,
				defaultGlobalNamespace:     tc.defaultGlobalNamespace, // This is the flag value from operator
			}

			// Simulate namespace state updates to activate filtering
			r.updateNamespaceState(context.Background(), globalNS)

			// Test default namespace behavior with the operator flag
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "default-service", Namespace: "default-ns"},
			})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result)

			svcImport, err := getServiceImport(c, types.NamespacedName{Name: "default-service", Namespace: "default-ns"})
			if tc.expectServiceImportCreated {
				require.NoError(t, err, tc.description)
				require.NotNil(t, svcImport, tc.description)
			} else {
				require.True(t, k8sApiErrors.IsNotFound(err), tc.description)
				require.Nil(t, svcImport, tc.description)
			}
		})
	}
}

func Test_mcsServiceImport_ConstructorIntegration(t *testing.T) {
	// Test that the defaultGlobalNamespace parameter is properly set
	globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}

	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		Build()

	testCases := []struct {
		name                   string
		defaultGlobalNamespace bool
	}{
		{
			name:                   "constructor with defaultGlobalNamespace=false",
			defaultGlobalNamespace: false,
		},
		{
			name:                   "constructor with defaultGlobalNamespace=true",
			defaultGlobalNamespace: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &mcsAPIServiceImportReconciler{
				Client:                     c,
				Logger:                     hivetest.Logger(t),
				cluster:                    localClusterName,
				globalServiceExports:       globalServiceExports,
				remoteClusterServiceSource: remoteClusterServiceSource,
				annotatedNamespaces:        sets.New[string](),
				globalNamespaces:           sets.New[string](),
				filteringActive:            false,
				defaultGlobalNamespace:     tc.defaultGlobalNamespace,
			}

			require.Equal(t, tc.defaultGlobalNamespace, r.defaultGlobalNamespace, "defaultGlobalNamespace should be set properly")
			require.False(t, r.filteringActive, "Filtering should not be active initially")
			require.Empty(t, r.annotatedNamespaces, "Annotated namespaces should be empty initially")
			require.Empty(t, r.globalNamespaces, "Global namespaces should be empty initially")
		})
	}
}

func Test_mcsServiceImport_ServiceExportConditions(t *testing.T) {
	// Test ServiceExport conditions for namespace filtering
	localNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "local-ns",
			Annotations: map[string]string{
				"clustermesh.cilium.io/global": "false",
			},
		},
	}

	localService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "local-service",
			Namespace: "local-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 9090}},
		},
	}

	localServiceExport := &mcsapiv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "local-service",
			Namespace:         "local-ns",
			CreationTimestamp: nowTime,
		},
	}

	fixtures := []client.Object{
		localNS,
		localService,
		localServiceExport,
	}

	c := fake.NewClientBuilder().
		WithObjects(fixtures...).
		WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
		WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
		WithScheme(testScheme()).
		Build()

	globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}

	r := &mcsAPIServiceImportReconciler{
		Client:                     c,
		Logger:                     hivetest.Logger(t),
		cluster:                    localClusterName,
		globalServiceExports:       globalServiceExports,
		remoteClusterServiceSource: remoteClusterServiceSource,
		annotatedNamespaces:        sets.New[string](),
		globalNamespaces:           sets.New[string](),
		filteringActive:            false,
		defaultGlobalNamespace:     false, // defaultGlobalNamespace = false
	}

	// Simulate namespace state updates
	r.updateNamespaceState(context.Background(), localNS)

	// Reconcile the local service (in a non-global namespace)
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "local-service", Namespace: "local-ns"},
	})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	// Verify ServiceExport has the correct conditions
	svcExport, err := getServiceExport(c, types.NamespacedName{Name: "local-service", Namespace: "local-ns"})
	require.NoError(t, err)
	require.NotNil(t, svcExport)

	// Check that NamespaceNotGlobal condition is set
	namespaceNotGlobalCondition := meta.FindStatusCondition(svcExport.Status.Conditions, ServiceExportNamespaceNotGlobal)
	require.NotNil(t, namespaceNotGlobalCondition)
	require.Equal(t, metav1.ConditionTrue, namespaceNotGlobalCondition.Status)
	require.Equal(t, "NamespaceNotGlobal", namespaceNotGlobalCondition.Reason)
	require.Contains(t, namespaceNotGlobalCondition.Message, "local-ns is not marked for global export")

	// Check that ServiceExportValid condition is set to False
	validCondition := meta.FindStatusCondition(svcExport.Status.Conditions, mcsapiv1alpha1.ServiceExportValid)
	require.NotNil(t, validCondition)
	require.Equal(t, metav1.ConditionFalse, validCondition.Status)
	require.Equal(t, "NamespaceNotGlobal", validCondition.Reason)
	require.Contains(t, validCondition.Message, "local-ns is not marked for global export")

	// Verify ServiceImport was not created
	svcImport, err := getServiceImport(c, types.NamespacedName{Name: "local-service", Namespace: "local-ns"})
	require.True(t, k8sApiErrors.IsNotFound(err))
	require.Nil(t, svcImport)
}

func Test_mcsServiceImport_NamespaceFilteringEdgeCases(t *testing.T) {
	// Test comprehensive edge cases for namespace filtering
	tests := []struct {
		name                       string
		defaultGlobalNamespace     bool
		namespaceAnnotations       map[string]string
		expectedServiceImportCount int
		expectedConditions         []string
		description                string
	}{
		{
			name:                   "multiple_global_namespaces_default_false",
			defaultGlobalNamespace: false,
			namespaceAnnotations: map[string]string{
				"global-1": "true",
				"global-2": "true",
				"local-1":  "false",
			},
			expectedServiceImportCount: 2, // Only global-1 and global-2
			expectedConditions:         []string{"local-1:" + ServiceExportNamespaceNotGlobal},
			description:                "Multiple global namespaces with local namespace should create selective ServiceImports",
		},
		{
			name:                   "mixed_annotations_default_true", 
			defaultGlobalNamespace: true,
			namespaceAnnotations: map[string]string{
				"explicit-global": "true",
				"explicit-local":  "false",
				"unannotated-ns":  "", // No annotation, should inherit default
			},
			expectedServiceImportCount: 2, // explicit-global and unannotated-ns
			expectedConditions:         []string{"explicit-local:" + ServiceExportNamespaceNotGlobal},
			description:                "Mixed annotations with default=true should handle unannotated namespace correctly",
		},
		{
			name:                   "all_local_namespaces",
			defaultGlobalNamespace: false,
			namespaceAnnotations: map[string]string{
				"local-1": "false",
				"local-2": "false", 
				"local-3": "false",
			},
			expectedServiceImportCount: 0, // No global namespaces
			expectedConditions:         []string{"local-1:" + ServiceExportNamespaceNotGlobal, "local-2:" + ServiceExportNamespaceNotGlobal, "local-3:" + ServiceExportNamespaceNotGlobal},
			description:                "All local namespaces should create no ServiceImports and set conditions on all",
		},
		{
			name:                   "annotation_value_edge_cases",
			defaultGlobalNamespace: false,
			namespaceAnnotations: map[string]string{
				"true-caps":     "True",   // Should be treated as local (only "true" is valid)
				"false-caps":    "False",  // Should be treated as local
				"invalid-value": "maybe",  // Should default to false (since default=false)
			},
			expectedServiceImportCount: 0, // All should be local
			expectedConditions:         []string{"true-caps:" + ServiceExportNamespaceNotGlobal, "false-caps:" + ServiceExportNamespaceNotGlobal, "invalid-value:" + ServiceExportNamespaceNotGlobal},
			description:                "Edge cases in annotation values should be handled correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().
				WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
				WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
				WithScheme(testScheme()).
				Build()
			
			globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
			remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}

			r := &mcsAPIServiceImportReconciler{
				Client:                     c,
				Logger:                     hivetest.Logger(t),
				cluster:                    localClusterName,
				globalServiceExports:       globalServiceExports,
				remoteClusterServiceSource: remoteClusterServiceSource,
				annotatedNamespaces:        sets.New[string](),
				globalNamespaces:           sets.New[string](),
				filteringActive:            false,
				defaultGlobalNamespace:     tt.defaultGlobalNamespace,
			}

			// Create namespaces and services
			namespaceCount := 0
			for ns := range tt.namespaceAnnotations {
				namespace := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: ns,
					},
				}
				
				if tt.namespaceAnnotations[ns] != "" {
					namespace.Annotations = map[string]string{
						"clustermesh.cilium.io/global": tt.namespaceAnnotations[ns],
					}
				}
				
				require.NoError(t, c.Create(context.Background(), namespace))

				// Create service in each namespace
				service := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: ns,
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{
							Port: 80,
						}},
					},
				}
				require.NoError(t, c.Create(context.Background(), service))

				// Create ServiceExport in each namespace
				svcExport := &mcsapiv1alpha1.ServiceExport{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: ns,
					},
				}
				require.NoError(t, c.Create(context.Background(), svcExport))
				
				// Update reconciler's namespace state to reflect the namespace annotation
				r.updateNamespaceState(context.Background(), namespace)
				namespaceCount++
			}

			// Reconcile for each namespace
			for ns := range tt.namespaceAnnotations {
				result, err := r.Reconcile(context.Background(), ctrl.Request{
					NamespacedName: types.NamespacedName{Name: "test-service", Namespace: ns},
				})
				require.NoError(t, err)
				require.Equal(t, ctrl.Result{}, result)
			}

			// Count ServiceImports created
			serviceImportList := &mcsapiv1alpha1.ServiceImportList{}
			err := c.List(context.Background(), serviceImportList)
			require.NoError(t, err)
			require.Equal(t, tt.expectedServiceImportCount, len(serviceImportList.Items), 
				"Expected %d ServiceImports for test '%s', got %d", tt.expectedServiceImportCount, tt.description, len(serviceImportList.Items))

			// Check conditions on ServiceExports
			for _, expectedCondition := range tt.expectedConditions {
				parts := strings.Split(expectedCondition, ":")
				require.Equal(t, 2, len(parts), "Invalid expected condition format: %s", expectedCondition)
				namespace := parts[0]
				conditionType := parts[1]

				svcExport := &mcsapiv1alpha1.ServiceExport{}
				err := c.Get(context.Background(), types.NamespacedName{Name: "test-service", Namespace: namespace}, svcExport)
				require.NoError(t, err)

				condition := meta.FindStatusCondition(svcExport.Status.Conditions, conditionType)
				require.NotNil(t, condition, "Expected condition %s on ServiceExport in namespace %s", conditionType, namespace)
				require.Equal(t, metav1.ConditionTrue, condition.Status)
			}
		})
	}
}

func Test_mcsServiceImport_DynamicNamespaceChanges(t *testing.T) {
	// Test dynamic changes to namespace annotations
	c := fake.NewClientBuilder().
		WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
		WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
		WithScheme(testScheme()).
		Build()
	
	globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}

	r := &mcsAPIServiceImportReconciler{
		Client:                     c,
		Logger:                     hivetest.Logger(t),
		cluster:                    localClusterName,
		globalServiceExports:       globalServiceExports,
		remoteClusterServiceSource: remoteClusterServiceSource,
		annotatedNamespaces:        sets.New[string](),
		globalNamespaces:           sets.New[string](),
		filteringActive:            false,
		defaultGlobalNamespace:     false,
	}

	// Create namespace and service
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dynamic-ns",
		},
	}
	require.NoError(t, c.Create(context.Background(), namespace))

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dynamic-service",
			Namespace: "dynamic-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 80}},
		},
	}
	require.NoError(t, c.Create(context.Background(), service))

	svcExport := &mcsapiv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dynamic-service",
			Namespace: "dynamic-ns",
		},
	}
	require.NoError(t, c.Create(context.Background(), svcExport))

	key := types.NamespacedName{Name: "dynamic-service", Namespace: "dynamic-ns"}

	// Initially global (no annotation means filtering is inactive, so all namespaces are global for backwards compatibility)
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	// Verify ServiceImport was created (backwards compatibility behavior)
	initialSvcImport, err := getServiceImport(c, key)
	require.NoError(t, err)
	require.NotNil(t, initialSvcImport)

	// Change to global
	namespace.Annotations = map[string]string{"clustermesh.cilium.io/global": "true"}
	err = c.Update(context.Background(), namespace)
	require.NoError(t, err)
	r.updateNamespaceState(context.Background(), namespace)
	
	result, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	// Verify ServiceImport created
	svcImport, err := getServiceImport(c, key)
	require.NoError(t, err)
	require.NotNil(t, svcImport)

	// Change back to local
	namespace.Annotations = map[string]string{"clustermesh.cilium.io/global": "false"}
	err = c.Update(context.Background(), namespace)
	require.NoError(t, err)
	r.updateNamespaceState(context.Background(), namespace)
	
	result, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	// Verify ServiceImport deleted
	_, err = getServiceImport(c, key)
	require.True(t, k8sApiErrors.IsNotFound(err))

	// Verify ServiceExport condition set
	svcExportUpdated := &mcsapiv1alpha1.ServiceExport{}
	err = c.Get(context.Background(), key, svcExportUpdated)
	require.NoError(t, err)

	condition := meta.FindStatusCondition(svcExportUpdated.Status.Conditions, ServiceExportNamespaceNotGlobal)
	require.NotNil(t, condition)
	require.Equal(t, metav1.ConditionTrue, condition.Status)
}

func Test_mcsServiceImport_BackwardsCompatibilityTransition(t *testing.T) {
	// Test transition from backwards compatibility mode to filtering mode
	c := fake.NewClientBuilder().
		WithStatusSubresource(&mcsapiv1alpha1.ServiceExport{}).
		WithStatusSubresource(&mcsapiv1alpha1.ServiceImport{}).
		WithScheme(testScheme()).
		Build()
	
	globalServiceExports := operator.NewGlobalServiceExportCache(metric.NewGauge(metric.GaugeOpts{}))
	remoteClusterServiceSource := &remoteClusterServiceExportSource{Logger: hivetest.Logger(t)}

	r := &mcsAPIServiceImportReconciler{
		Client:                     c,
		Logger:                     hivetest.Logger(t),
		cluster:                    localClusterName,
		globalServiceExports:       globalServiceExports,
		remoteClusterServiceSource: remoteClusterServiceSource,
		annotatedNamespaces:        sets.New[string](),
		globalNamespaces:           sets.New[string](),
		filteringActive:            false, // Start in backwards compatibility mode
		defaultGlobalNamespace:     false,
	}

	// Create namespaces and services
	namespaces := []string{"ns1", "ns2", "ns3"}
	for _, ns := range namespaces {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		}
		require.NoError(t, c.Create(context.Background(), namespace))

		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: ns,
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 80}},
			},
		}
		require.NoError(t, c.Create(context.Background(), service))

		svcExport := &mcsapiv1alpha1.ServiceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service", 
				Namespace: ns,
			},
		}
		require.NoError(t, c.Create(context.Background(), svcExport))
	}

	// In backwards compatibility mode, all should create ServiceImports
	for _, ns := range namespaces {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "test-service", Namespace: ns},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	}

	// Verify all ServiceImports created
	serviceImportList := &mcsapiv1alpha1.ServiceImportList{}
	err := c.List(context.Background(), serviceImportList)
	require.NoError(t, err)
	require.Equal(t, 3, len(serviceImportList.Items), "All namespaces should have ServiceImports in backwards compatibility mode")

	// Transition to filtering mode by adding an annotation
	ns1 := &corev1.Namespace{}
	err = c.Get(context.Background(), types.NamespacedName{Name: "ns1"}, ns1)
	require.NoError(t, err)
	
	ns1.Annotations = map[string]string{"clustermesh.cilium.io/global": "true"}
	err = c.Update(context.Background(), ns1)
	require.NoError(t, err)
	r.updateNamespaceState(context.Background(), ns1) // Only ns1 becomes global

	// Re-reconcile all services
	for _, ns := range namespaces {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "test-service", Namespace: ns},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	}

	// Verify only ns1 has ServiceImport now
	serviceImportList = &mcsapiv1alpha1.ServiceImportList{}
	err = c.List(context.Background(), serviceImportList)
	require.NoError(t, err)
	require.Equal(t, 1, len(serviceImportList.Items), "Only global namespace should have ServiceImport after filtering activation")
	require.Equal(t, "ns1", serviceImportList.Items[0].Namespace)

	// Verify conditions set on ns2 and ns3
	for _, ns := range []string{"ns2", "ns3"} {
		svcExport := &mcsapiv1alpha1.ServiceExport{}
		err := c.Get(context.Background(), types.NamespacedName{Name: "test-service", Namespace: ns}, svcExport)
		require.NoError(t, err)

		condition := meta.FindStatusCondition(svcExport.Status.Conditions, ServiceExportNamespaceNotGlobal)
		require.NotNil(t, condition, "Non-global namespace %s should have NamespaceNotGlobal condition", ns)
		require.Equal(t, metav1.ConditionTrue, condition.Status)
	}
}
