// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8sApiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
