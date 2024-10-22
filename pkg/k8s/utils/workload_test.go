// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright Istio Authors
// Copyright Authors of Hubble

// Tests come from
// https://github.com/istio/istio/blob/1aca7a67afd7b3e1d24fafb2fbfbeaf1e41534c0/pkg/kube/util_test.go
// and have been modified to work with our version of GetWorkloadMetaFromPod.

package utils

import (
	"reflect"
	"testing"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestDeploymentMetadata(t *testing.T) {
	controller := true
	tests := []struct {
		name               string
		pod                *slim_corev1.Pod
		wantTypeMetadata   slim_metav1.TypeMeta
		wantObjectMetadata slim_metav1.ObjectMeta
		expectOK           bool
	}{
		{
			name: "deployment-name-deploy",
			pod:  podForDeployment("deploy", "12345"),
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "Deployment",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "deploy",
				GenerateName: "deploy-12345-",
				Labels: map[string]string{
					"pod-template-hash": "12345",
				},
			},
			expectOK: true,
		},
		{
			name: "deployment-name-deploy2",
			pod:  podForDeployment("deploy2", "45678"),
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "Deployment",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "deploy2",
				GenerateName: "deploy2-45678-",
				Labels: map[string]string{
					"pod-template-hash": "45678",
				},
			},
			expectOK: true,
		},
		{
			name: "non-deployment",
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:         "replicaset0-abcd0",
					GenerateName: "replicaset0-",
					OwnerReferences: []slim_metav1.OwnerReference{{
						Controller: &controller,
						Kind:       "ReplicaSet",
						Name:       "replicaset0",
					}},
				},
			},
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "ReplicaSet",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "replicaset0",
				GenerateName: "replicaset0-",
			},
			expectOK: true,
		},
		{
			name: "bare-pod",
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "some-pod",
				},
			},
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotObjectMeta, gotTypeMeta, ok := GetWorkloadMetaFromPod(tt.pod)
			if tt.expectOK != ok {
				t.Fatalf("expected ok=%t, got ok=%t", tt.expectOK, ok)
			}
			if ok {
				if !reflect.DeepEqual(gotObjectMeta, tt.wantObjectMetadata) {
					t.Errorf("Object metadata got %+v want %+v", gotObjectMeta, tt.wantObjectMetadata)
				}
				if !reflect.DeepEqual(gotTypeMeta, tt.wantTypeMetadata) {
					t.Errorf("Type metadata got %+v want %+v", gotTypeMeta, tt.wantTypeMetadata)
				}
			}
		})
	}
}

func podForDeployment(deploymentName string, hash string) *slim_corev1.Pod {
	controller := true
	labels := make(map[string]string)
	if hash != "" {
		labels["pod-template-hash"] = hash
	}
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:         deploymentName + "-" + hash + "-" + "asdf0",
			GenerateName: deploymentName + "-" + hash + "-",
			OwnerReferences: []slim_metav1.OwnerReference{{
				Controller: &controller,
				Kind:       "ReplicaSet",
				Name:       deploymentName + "-" + hash,
			}},
			Labels: labels,
		},
	}
}

func TestCronJobMetadata(t *testing.T) {
	tests := []struct {
		name               string
		jobName            string
		wantTypeMetadata   slim_metav1.TypeMeta
		wantObjectMetadata slim_metav1.ObjectMeta
	}{
		{
			name:    "cron-job-name-sec",
			jobName: "sec-1234567890",
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "CronJob",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "sec",
				GenerateName: "sec-1234567890-pod",
			},
		},
		{
			name:    "cron-job-name-min",
			jobName: "min-12345678",
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "CronJob",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "min",
				GenerateName: "min-12345678-pod",
			},
		},
		{
			name:    "non-cron-job-name",
			jobName: "job-123",
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "Job",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "job-123",
				GenerateName: "job-123-pod",
			},
		},
	}

	for _, tt := range tests {
		controller := true
		t.Run(tt.name, func(t *testing.T) {
			gotObjectMeta, gotTypeMeta, ok := GetWorkloadMetaFromPod(
				&slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						GenerateName: tt.jobName + "-pod",
						OwnerReferences: []slim_metav1.OwnerReference{{
							Controller: &controller,
							Kind:       "Job",
							Name:       tt.jobName,
						}},
					},
				},
			)
			if !ok {
				t.Fatalf("expected ok=true, got ok=%t", ok)
			}
			if ok {
				if !reflect.DeepEqual(gotObjectMeta, tt.wantObjectMetadata) {
					t.Errorf("Object metadata got %+v want %+v", gotObjectMeta, tt.wantObjectMetadata)
				}
				if !reflect.DeepEqual(gotTypeMeta, tt.wantTypeMetadata) {
					t.Errorf("Type metadata got %+v want %+v", gotTypeMeta, tt.wantTypeMetadata)
				}
			}
		})
	}
}

func TestDeploymentConfigMetadata(t *testing.T) {
	tests := []struct {
		name               string
		pod                *slim_corev1.Pod
		wantTypeMetadata   slim_metav1.TypeMeta
		wantObjectMetadata slim_metav1.ObjectMeta
	}{
		{
			name: "deployconfig-name-deploy",
			pod:  podForDeploymentConfig("deploy", true),
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "DeploymentConfig",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "deploy",
				GenerateName: "deploy-rc-pod",
				Labels:       map[string]string{},
			},
		},
		{
			name: "deployconfig-name-deploy2",
			pod:  podForDeploymentConfig("deploy2", true),
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "DeploymentConfig",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "deploy2",
				GenerateName: "deploy2-rc-pod",
				Labels:       map[string]string{},
			},
		},
		{
			name: "non-deployconfig-label",
			pod:  podForDeploymentConfig("dep", false),
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "ReplicationController",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "dep-rc",
				GenerateName: "dep-rc-pod",
				Labels:       map[string]string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotObjectMeta, gotTypeMeta, ok := GetWorkloadMetaFromPod(tt.pod)
			if !ok {
				t.Fatalf("expected ok=true, got ok=%t", ok)
			}
			if !reflect.DeepEqual(gotObjectMeta, tt.wantObjectMetadata) {
				t.Errorf("Object metadata got %+v want %+v", gotObjectMeta, tt.wantObjectMetadata)
			}
			if !reflect.DeepEqual(gotTypeMeta, tt.wantTypeMetadata) {
				t.Errorf("Type metadata got %+v want %+v", gotTypeMeta, tt.wantTypeMetadata)
			}
		})
	}
}

func podForDeploymentConfig(deployConfigName string, hasDeployConfigLabel bool) *slim_corev1.Pod {
	controller := true
	labels := make(map[string]string)
	if hasDeployConfigLabel {
		labels["deploymentconfig"] = deployConfigName
	}
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			GenerateName: deployConfigName + "-rc-pod",
			OwnerReferences: []slim_metav1.OwnerReference{{
				Controller: &controller,
				Kind:       "ReplicationController",
				Name:       deployConfigName + "-rc",
			}},
			Labels: labels,
		},
	}
}

func TestStatefulSetMetadata(t *testing.T) {
	tests := []struct {
		name               string
		statefulsetName    string
		wantTypeMetadata   slim_metav1.TypeMeta
		wantObjectMetadata slim_metav1.ObjectMeta
	}{
		{
			name:            "statefulset-name-foo",
			statefulsetName: "foo",
			wantTypeMetadata: slim_metav1.TypeMeta{
				Kind: "StatefulSet",
			},
			wantObjectMetadata: slim_metav1.ObjectMeta{
				Name:         "foo",
				GenerateName: "foo-",
			},
		},
	}

	for _, tt := range tests {
		controller := true
		t.Run(tt.name, func(t *testing.T) {
			gotObjectMeta, gotTypeMeta, ok := GetWorkloadMetaFromPod(
				&slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						GenerateName: tt.statefulsetName + "-",
						OwnerReferences: []slim_metav1.OwnerReference{{
							Controller: &controller,
							Kind:       "StatefulSet",
							Name:       tt.statefulsetName,
						}},
					},
				},
			)
			if !ok {
				t.Fatalf("expected ok=true, got ok=%t", ok)
			}
			if ok {
				if !reflect.DeepEqual(gotObjectMeta, tt.wantObjectMetadata) {
					t.Errorf("Object metadata got %+v want %+v", gotObjectMeta, tt.wantObjectMetadata)
				}
				if !reflect.DeepEqual(gotTypeMeta, tt.wantTypeMetadata) {
					t.Errorf("Type metadata got %+v want %+v", gotTypeMeta, tt.wantTypeMetadata)
				}
			}
		})
	}
}
