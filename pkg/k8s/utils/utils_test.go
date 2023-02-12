// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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

func TestValidIPs(t *testing.T) {
	tests := []struct {
		name string
		args slim_corev1.PodStatus
		want []string
	}{
		{
			name: "podip is nil",
			args: slim_corev1.PodStatus{
				HostIP: "127.0.0.1",
			},
			want: nil,
		},

		{
			name: "one pod ip",
			args: slim_corev1.PodStatus{
				HostIP: "127.0.0.1",
				PodIPs: []slim_corev1.PodIP{
					{
						IP: "127.0.0.2",
					},
				},
			},
			want: []string{"127.0.0.2"},
		},

		{
			name: "duplicate ip",
			args: slim_corev1.PodStatus{
				HostIP: "127.0.0.1",
				PodIPs: []slim_corev1.PodIP{
					{
						IP: "127.0.0.2",
					},
					{
						IP: "127.0.0.2",
					},
				},
			},
			want: []string{"127.0.0.2"},
		},
		{
			name: "multiple pod ip",
			args: slim_corev1.PodStatus{
				HostIP: "127.0.0.1",
				PodIPs: []slim_corev1.PodIP{
					{
						IP: "10.0.0.1",
					},
					{
						IP: "127.0.0.2",
					},
					{
						IP: "127.0.0.3",
					},
				},
			},
			want: []string{"10.0.0.1", "127.0.0.2", "127.0.0.3"},
		},
		{
			name: "have empty pod ip",
			args: slim_corev1.PodStatus{
				HostIP: "127.0.0.1",
				PodIPs: []slim_corev1.PodIP{
					{
						IP: "127.0.0.2",
					},
					{
						IP: "",
					},
				},
			},
			want: []string{"127.0.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidIPs(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidIPs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPodRunning(t *testing.T) {
	tests := []struct {
		name string
		args slim_corev1.PodStatus
		want bool
	}{
		{
			name: "Pod is not Running",
			args: slim_corev1.PodStatus{
				HostIP: "127.0.0.1",
				Phase:  "Succeeded",
			},
			want: false,
		},
		{
			name: "Pod is Running",
			args: slim_corev1.PodStatus{
				HostIP: "127.0.0.1",
				Phase:  "Running",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPodRunning(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TestIsPodRunning() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetLatestPodReadiness(t *testing.T) {
	podReadyconditiontrue := slim_corev1.PodCondition{
		Type:               slim_corev1.PodReady,
		Status:             slim_corev1.ConditionTrue,
		LastProbeTime:      slim_metav1.Now(),
		LastTransitionTime: slim_metav1.Now(),
		Reason:             "",
		Message:            "",
	}
	podReadyconditionfalse := slim_corev1.PodCondition{
		Type:               slim_corev1.PodReady,
		Status:             slim_corev1.ConditionFalse,
		LastProbeTime:      slim_metav1.Now(),
		LastTransitionTime: slim_metav1.Now(),
		Reason:             "",
		Message:            "",
	}
	podReadyconditionUnknown := slim_corev1.PodCondition{
		Type:               slim_corev1.PodReady,
		Status:             slim_corev1.ConditionUnknown,
		LastProbeTime:      slim_metav1.Now(),
		LastTransitionTime: slim_metav1.Now(),
		Reason:             "",
		Message:            "",
	}
	podScheduled := slim_corev1.PodCondition{
		Type:               slim_corev1.PodScheduled,
		Status:             slim_corev1.ConditionTrue,
		LastProbeTime:      slim_metav1.Now(),
		LastTransitionTime: slim_metav1.Now(),
		Reason:             "",
		Message:            "",
	}
	tests := []struct {
		name string
		args slim_corev1.PodStatus
		want slim_corev1.ConditionStatus
	}{
		{
			name: "conditions are podReadyconditiontrue, podReadyconditionfalse and podReadyconditionUnknown",
			args: slim_corev1.PodStatus{
				HostIP:     "127.0.0.1",
				Conditions: []slim_corev1.PodCondition{podReadyconditiontrue, podReadyconditionfalse, podReadyconditionUnknown},
			},
			want: "True",
		},
		{
			name: "conditions are podReadyconditionfalse and podScheduled",
			args: slim_corev1.PodStatus{
				HostIP:     "127.0.0.1",
				Conditions: []slim_corev1.PodCondition{podReadyconditionfalse, podScheduled},
			},
			want: "False",
		},
		{
			name: "conditions are podReadyconditionUnknown and podReadyconditiontrue",
			args: slim_corev1.PodStatus{
				HostIP:     "127.0.0.1",
				Conditions: []slim_corev1.PodCondition{podReadyconditionUnknown, podReadyconditiontrue},
			},
			want: "Unknown",
		},
		{
			name: "conditions are podScheduled and podReadyconditiontrue",
			args: slim_corev1.PodStatus{
				HostIP:     "127.0.0.1",
				Conditions: []slim_corev1.PodCondition{podScheduled, podReadyconditiontrue},
			},
			want: "True",
		},
		{
			name: "conditions is podScheduled",
			args: slim_corev1.PodStatus{
				HostIP:     "127.0.0.1",
				Conditions: []slim_corev1.PodCondition{podScheduled},
			},
			want: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetLatestPodReadiness(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetLatestPodReadiness() = %v, want %v", got, tt.want)
			}
		})
	}
}
