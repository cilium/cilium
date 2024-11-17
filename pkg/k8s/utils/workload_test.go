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

	"github.com/cilium/cilium/api/v1/models"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestDeploymentMetadata(t *testing.T) {
	controller := true
	tests := []struct {
		name     string
		pod      *slim_corev1.Pod
		want     *models.Workload
		expectOK bool
	}{
		{
			name: "deployment-name-deploy",
			pod:  podForDeployment("deploy", "12345"),
			want: &models.Workload{
				Kind: "Deployment",
				Name: "deploy",
			},
			expectOK: true,
		},
		{
			name: "deployment-name-deploy2",
			pod:  podForDeployment("deploy2", "45678"),
			want: &models.Workload{
				Kind: "Deployment",
				Name: "deploy2",
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
			want: &models.Workload{
				Kind: "ReplicaSet",
				Name: "replicaset0",
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
			got, ok := GetWorkloadFromPod(tt.pod)
			if tt.expectOK != ok {
				t.Fatalf("expected ok=%t, got ok=%t", tt.expectOK, ok)
			}
			if ok {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Object metadata got %+v want %+v", got, tt.want)
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
		workload           *models.Workload
		wantObjectMetadata slim_metav1.ObjectMeta
	}{
		{
			name:    "cron-job-name-sec",
			jobName: "sec-1234567890",
			workload: &models.Workload{
				Kind: "CronJob",
				Name: "sec",
			},
		},
		{
			name:    "cron-job-name-min",
			jobName: "min-12345678",
			workload: &models.Workload{
				Kind: "CronJob",
				Name: "min",
			},
		},
		{
			name:    "non-cron-job-name",
			jobName: "job-123",
			workload: &models.Workload{
				Kind: "Job",
				Name: "job-123",
			},
		},
	}

	for _, tt := range tests {
		controller := true
		t.Run(tt.name, func(t *testing.T) {
			got, ok := GetWorkloadFromPod(
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
				if !reflect.DeepEqual(got, tt.workload) {
					t.Errorf("Object metadata got %+v want %+v", got, tt.workload)
				}
			}
		})
	}
}

func TestDeploymentConfigMetadata(t *testing.T) {
	tests := []struct {
		name string
		pod  *slim_corev1.Pod
		want *models.Workload
	}{
		{
			name: "deployconfig-name-deploy",
			pod:  podForDeploymentConfig("deploy", true),
			want: &models.Workload{
				Kind: "DeploymentConfig",
				Name: "deploy",
			},
		},
		{
			name: "deployconfig-name-deploy2",
			pod:  podForDeploymentConfig("deploy2", true),
			want: &models.Workload{
				Kind: "DeploymentConfig",
				Name: "deploy2",
			},
		},
		{
			name: "non-deployconfig-label",
			pod:  podForDeploymentConfig("dep", false),
			want: &models.Workload{
				Kind: "ReplicationController",
				Name: "dep-rc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := GetWorkloadFromPod(tt.pod)
			if !ok {
				t.Fatalf("expected ok=true, got ok=%t", ok)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Object metadata got %+v want %+v", got, tt.want)
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
		name            string
		statefulsetName string
		want            *models.Workload
	}{
		{
			name:            "statefulset-name-foo",
			statefulsetName: "foo",
			want: &models.Workload{
				Kind: "StatefulSet",
				Name: "foo",
			},
		},
	}

	for _, tt := range tests {
		controller := true
		t.Run(tt.name, func(t *testing.T) {
			got, ok := GetWorkloadFromPod(
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
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Object metadata got %+v want %+v", got, tt.want)
				}
			}
		})
	}
}
