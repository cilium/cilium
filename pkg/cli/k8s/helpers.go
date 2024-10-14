// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubectl/pkg/util/podutils"
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

// GetFirstPodForService returns the first pod in the list of pods matching the service selector,
// sorted from most to less active (see `podutils.ActivePods` for more details).
func (c *Client) GetFirstPodForService(ctx context.Context, svc *corev1.Service) (*corev1.Pod, error) {
	selector := labels.SelectorFromSet(svc.Spec.Selector)
	podList, err := c.ListPods(ctx, svc.Namespace, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, fmt.Errorf("failed to get list of pods for service %q: %w", svc.Name, err)
	}
	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no pods found for service: %s", svc.Name)
	}
	if len(podList.Items) == 1 {
		return &podList.Items[0], nil
	}

	pods := make([]*corev1.Pod, 0, len(podList.Items))
	for _, pod := range podList.Items {
		pods = append(pods, &pod)
	}
	sortBy := func(pods []*corev1.Pod) sort.Interface { return sort.Reverse(podutils.ActivePods(pods)) }
	sort.Sort(sortBy(pods))

	return pods[0], nil
}
