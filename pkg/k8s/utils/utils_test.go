// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package utils

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type fakeCfg struct {
	proxyName string
}

func (f *fakeCfg) K8sServiceProxyNameValue() string {
	return f.proxyName
}

func TestServiceProxyName(t *testing.T) {
	client := fake.NewSimpleClientset()

	svc1 := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "test-svc-1",
		Labels: map[string]string{
			serviceProxyNameLabel: "foo",
		},
	}}
	svc2 := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "test-svc-2",
		Labels: map[string]string{
			serviceProxyNameLabel: "bar",
		},
	}}
	svc3 := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "test-svc-3",
	}}

	for _, svc := range []*corev1.Service{svc1, svc2, svc3} {
		_, err := client.CoreV1().Services("test-ns").Create(context.TODO(), svc, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create svc %v: %s", svc, err)
		}
	}

	// Should return only test-svc-1 which has the service-proxy-name=foo
	cfg := &fakeCfg{proxyName: "foo"}
	optMod, _ := GetServiceListOptionsModifier(cfg)
	options := metav1.ListOptions{}
	optMod(&options)
	svcs, err := client.CoreV1().Services("test-ns").List(context.TODO(), options)
	if err != nil {
		t.Fatalf("Failed to list services: %s", err)
	}
	if len(svcs.Items) != 1 || svcs.Items[0].ObjectMeta.Name != "test-svc-1" {
		t.Fatalf("Expected test-svc-1, retrieved: %v", svcs)
	}

	// Should return only test-svc-3 which doesn't have any service-proxy-name
	cfg = &fakeCfg{proxyName: ""}
	optMod, _ = GetServiceListOptionsModifier(cfg)
	options = metav1.ListOptions{}
	optMod(&options)
	svcs, err = client.CoreV1().Services("test-ns").List(context.TODO(), options)
	if err != nil {
		t.Fatalf("Failed to list services: %s", err)
	}
	if len(svcs.Items) != 1 || svcs.Items[0].ObjectMeta.Name != "test-svc-3" {
		t.Fatalf("Expected test-svc-3, retrieved: %v", svcs)
	}
}

func TestSanitizePodLabels(t *testing.T) {
	namespaceLabelKey := "wow-very-key"
	namespaceMetaLabelKey := joinPath(k8sconst.PodNamespaceMetaLabels, namespaceLabelKey)
	testedLabels := map[string]string{
		k8sconst.PodNamespaceLabel:         "fake-namespace",
		k8sconst.PolicyLabelServiceAccount: "fake-sa",
		k8sconst.PolicyLabelCluster:        "fake-cluster-name",
		namespaceMetaLabelKey:              "fake-namespace-label-val",
		k8sconst.PodNameLabel:              "fake-pod-name",
	}
	trueNamespace := "true-namespace"
	trueSA := "true-sa"
	trueClusterName := "true-cluster-name"
	trueNamespaceLabelValue := "true-value-for-key"

	namespace := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{Name: trueNamespace,
			Labels: map[string]string{
				namespaceLabelKey: trueNamespaceLabelValue,
			}}}
	labels := SanitizePodLabels(testedLabels, namespace, trueSA, trueClusterName)

	ns, ok := labels[k8sconst.PodNamespaceLabel]
	if !ok {
		t.Errorf("namespace label not found")
	}
	if ns != trueNamespace {
		t.Errorf("namespace label not set to %s, set to %s instead", trueNamespace, namespace)
	}

	sa, ok := labels[k8sconst.PolicyLabelServiceAccount]
	if !ok {
		t.Errorf("sa label not found")
	}
	if sa != trueSA {
		t.Errorf("sa label not set to %s, set to %s instead", trueSA, sa)
	}

	clusterName, ok := labels[k8sconst.PolicyLabelCluster]
	if !ok {
		t.Errorf("cluster name label not found")
	}
	if clusterName != trueClusterName {
		t.Errorf("cluster name label not set to %s, set to %s instead", trueClusterName, clusterName)
	}

	namespaceMetaLabel, ok := labels[namespaceMetaLabelKey]
	if !ok {
		t.Errorf("namespace meta label not found")
	}
	if namespaceMetaLabel != trueNamespaceLabelValue {
		t.Errorf("namespace meta label not set to %s, set to %s instead", trueNamespaceLabelValue, namespaceMetaLabel)
	}

	labels = SanitizePodLabels(testedLabels, namespace, "", trueClusterName)
	sa, ok = labels[k8sconst.PolicyLabelServiceAccount]
	if ok {
		t.Errorf("Expected service account label to be deleted, got %s instead", sa)
	}
}
