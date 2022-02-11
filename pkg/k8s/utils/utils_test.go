// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package utils

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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
