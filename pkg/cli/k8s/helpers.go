// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

func NewServiceAccount(name string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func NewClusterRoleBinding(name, namespace, serviceAccount string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccount,
				Namespace: namespace,
			},
		},
	}
}

func NewIngressClass(name, controllerName string) *networkingv1.IngressClass {
	return &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.IngressClassSpec{
			Controller: controllerName,
		},
	}
}

func NewSecret(name, namespace string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
		Type: corev1.SecretTypeOpaque,
	}
}

// NewTLSSecret return a Secret of the type kubernetes.io/tls. Note that for
// this kind of Secret, both tls.key and tls.crt are required in data.
func NewTLSSecret(name, namespace string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
		Type: corev1.SecretTypeTLS,
	}
}

// Describe returns the Kubernetes type and resource information for an object
func (c *Client) Describe(obj runtime.Object) (gvk schema.GroupVersionKind, resource schema.GroupVersionResource, err error) {
	// first, determine the GroupVersionKind and Resource for the given object
	gvks, _, _ := scheme.Scheme.ObjectKinds(obj)
	if len(gvks) != 1 {
		err = fmt.Errorf("Could not get GroupVersionKind")
		return
	}

	gvk = gvks[0]

	// Convert the GroupVersionKind in to a Resource
	restMapper, err := c.RESTClientGetter.ToRESTMapper()
	if err != nil {
		return
	}
	rm, err := restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return
	}
	resource = rm.Resource
	return
}
