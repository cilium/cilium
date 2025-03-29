// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8sApiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	mcsapicontrollers "sigs.k8s.io/mcs-api/controllers"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/annotation"
)

var (
	typeMetaSvcImport = metav1.TypeMeta{
		Kind:       "ServiceImport",
		APIVersion: mcsapiv1alpha1.GroupVersion.String(),
	}
	typeMetaSvcExport = metav1.TypeMeta{
		Kind:       "ServiceExport",
		APIVersion: mcsapiv1alpha1.GroupVersion.String(),
	}

	mcsFixtures = []client.Object{
		&mcsapiv1alpha1.ServiceExport{
			TypeMeta: typeMetaSvcExport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full",
				Namespace: "default",
			},
		},
		&mcsapiv1alpha1.ServiceImport{
			TypeMeta: typeMetaSvcImport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full",
				Namespace: "default",
				Annotations: map[string]string{
					annotation.GlobalService: "not-used",
					"test-annotation":        "copied",
				},
				Labels: map[string]string{
					mcsapiv1alpha1.LabelSourceCluster: "not-used",
					mcsapiv1alpha1.LabelServiceName:   "not-used",
					"test-label":                      "copied",
				},
			},
			Spec: mcsapiv1alpha1.ServiceImportSpec{
				Ports: []mcsapiv1alpha1.ServicePort{{
					Name: "my-port-1",
					Port: 42,
				}, {
					Name: "my-port-target-port",
					Port: 4242,
				}},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"selector": "value",
				},
				Ports: []corev1.ServicePort{{
					Name: "not-used",
					Port: 43,
				}, {
					Name:       "my-port-target-port",
					Port:       4242,
					TargetPort: intstr.FromString("test-target-port"),
				}},
			},
		},

		&mcsapiv1alpha1.ServiceExport{
			TypeMeta: typeMetaSvcExport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update",
				Namespace: "default",
			},
		},
		&mcsapiv1alpha1.ServiceImport{
			TypeMeta: typeMetaSvcImport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update",
				Namespace: "default",
				Annotations: map[string]string{
					"test-annotation": "copied",
				},
				Labels: map[string]string{
					"test-label": "copied",
				},
			},
			Spec: mcsapiv1alpha1.ServiceImportSpec{
				Ports: []mcsapiv1alpha1.ServicePort{{
					Name: "my-port-1",
					Port: 42,
				}, {
					Name: "my-port-target-port",
					Port: 4242,
				}},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "full-update",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"selector": "value",
				},
				Ports: []corev1.ServicePort{{
					Name: "not-used",
					Port: 43,
				}, {
					Name:       "my-port-target-port",
					Port:       4242,
					TargetPort: intstr.FromString("test-target-port"),
				}},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      derivedName(types.NamespacedName{Name: "full-update", Namespace: "default"}),
				Namespace: "default",
			},
		},

		&mcsapiv1alpha1.ServiceImport{
			TypeMeta: typeMetaSvcImport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "import-only",
				Namespace: "default",
				Annotations: map[string]string{
					annotation.GlobalService: "not-used",
				},
				Labels: map[string]string{
					mcsapiv1alpha1.LabelSourceCluster: "not-used",
				},
			},
			Spec: mcsapiv1alpha1.ServiceImportSpec{
				Ports: []mcsapiv1alpha1.ServicePort{{
					Name: "my-port-2",
					Port: 42,
				}},
			},
		},

		&mcsapiv1alpha1.ServiceImport{
			TypeMeta: typeMetaSvcImport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "import-and-local",
				Namespace: "default",
			},
			Spec: mcsapiv1alpha1.ServiceImportSpec{
				Ports: []mcsapiv1alpha1.ServicePort{{
					Name: "my-port-2",
					Port: 42,
				}},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "import-and-local",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"selector": "value",
				},
			},
		},

		&mcsapiv1alpha1.ServiceExport{
			TypeMeta: typeMetaSvcExport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "export-only",
				Namespace: "default",
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "export-only",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{
					Name: "my-port-3",
				}},
				ClusterIP: corev1.ClusterIPNone,
			},
		},

		&mcsapiv1alpha1.ServiceExport{
			TypeMeta: typeMetaSvcExport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "export-no-svc",
				Namespace: "default",
			},
		},

		&mcsapiv1alpha1.ServiceImport{
			TypeMeta: typeMetaSvcImport,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "switch-to-headless",
				Namespace: "default",
			},
			Spec: mcsapiv1alpha1.ServiceImportSpec{
				Type: mcsapiv1alpha1.Headless,
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      derivedName(types.NamespacedName{Name: "switch-to-headless", Namespace: "default"}),
				Namespace: "default",
			},
		},
	}
)

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(mcsapiv1alpha1.AddToScheme(scheme))
	return scheme
}

func Test_mcsDerivedService_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithObjects(mcsFixtures...).
		WithScheme(testScheme()).
		Build()
	r := &mcsAPIServiceReconciler{
		Client: c,
		Logger: hivetest.Logger(t),
	}

	t.Run("Test service creation/update with export and import", func(t *testing.T) {
		for _, name := range []string{"full", "full-update"} {
			key := types.NamespacedName{
				Name:      name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			keyDerived := types.NamespacedName{
				Name:      derivedName(key),
				Namespace: key.Namespace,
			}
			svc := &corev1.Service{}
			err = c.Get(context.Background(), keyDerived, svc)
			require.NoError(t, err)

			require.Len(t, svc.OwnerReferences, 1)
			require.Equal(t, "ServiceImport", svc.OwnerReferences[0].Kind)

			require.Equal(t, key.Name, svc.Labels[mcsapiv1alpha1.LabelServiceName])
			require.Equal(t, "copied", svc.Labels["test-label"])

			require.Equal(t, "true", svc.Annotations[annotation.GlobalService])
			require.Equal(t, "copied", svc.Annotations["test-annotation"])

			require.Len(t, svc.Spec.Ports, 2)
			require.Equal(t, "my-port-1", svc.Spec.Ports[0].Name)
			require.Equal(t, "my-port-target-port", svc.Spec.Ports[1].Name)
			require.Equal(t, "test-target-port", svc.Spec.Ports[1].TargetPort.String())

			svcImport := &mcsapiv1alpha1.ServiceImport{}
			err = c.Get(context.Background(), key, svcImport)
			require.NoError(t, err)
			require.Equal(t, keyDerived.Name, svcImport.Annotations[mcsapicontrollers.DerivedServiceAnnotation])
		}
	})

	t.Run("Test service creation with only import", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "import-only",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		keyDerived := types.NamespacedName{
			Name:      derivedName(key),
			Namespace: key.Namespace,
		}
		svc := &corev1.Service{}
		err = c.Get(context.Background(), keyDerived, svc)
		require.NoError(t, err)

		require.Len(t, svc.OwnerReferences, 1)
		require.Equal(t, "ServiceImport", svc.OwnerReferences[0].Kind)

		require.Nil(t, svc.Spec.Selector)

		require.Equal(t, "true", svc.Annotations[annotation.GlobalService])

		require.Len(t, svc.Spec.Ports, 1)
		require.Equal(t, "my-port-2", svc.Spec.Ports[0].Name)
	})

	t.Run("Test service creation with import and local svc", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "import-and-local",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		keyDerived := types.NamespacedName{
			Name:      derivedName(key),
			Namespace: key.Namespace,
		}
		svc := &corev1.Service{}
		err = c.Get(context.Background(), keyDerived, svc)
		require.NoError(t, err)

		require.Nil(t, svc.Spec.Selector)
	})

	t.Run("Test service creation with only export", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "export-only",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		keyDerived := types.NamespacedName{
			Name:      derivedName(key),
			Namespace: key.Namespace,
		}
		svc := &corev1.Service{}
		err = c.Get(context.Background(), keyDerived, svc)
		require.True(t, k8sApiErrors.IsNotFound(err), "Should return not found error")
	})

	t.Run("Test service creation with export but no exported service", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "export-no-svc",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		keyDerived := types.NamespacedName{
			Name:      derivedName(key),
			Namespace: key.Namespace,
		}
		svc := &corev1.Service{}
		err = c.Get(context.Background(), keyDerived, svc)
		require.True(t, k8sApiErrors.IsNotFound(err), "Should return not found error")
	})

	t.Run("Test service recreation to headless service", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "switch-to-headless",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		keyDerived := types.NamespacedName{
			Name:      derivedName(key),
			Namespace: key.Namespace,
		}
		svc := &corev1.Service{}
		err = c.Get(context.Background(), keyDerived, svc)
		require.NoError(t, err)

		require.Equal(t, corev1.ClusterIPNone, svc.Spec.ClusterIP)
	})
}
