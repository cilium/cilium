package types

import (
	"github.com/cilium/cilium/api/v1/models"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestGetWorkloadFromPod(t *testing.T) {
	expectedWorkload := Workload{
		Name:      "foo",
		Namespace: "foo",
		Kind:      "Deployment",
	}
	controller := true
	k8sPod := &slim_corev1.Pod{
		TypeMeta: slim_metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:         "foo-xxddxx",
			GenerateName: "foo-",
			Namespace:    "foo",
			Labels: map[string]string{
				"foo":  "xxddxx",
				"foo1": "xdx",
			},
			OwnerReferences: []slim_metav1.OwnerReference{
				{
					Kind:       "Deployment",
					Name:       "foo",
					Controller: &controller,
				},
			},
		},
	}
	w, err := GetWorkloadDataFromPod(k8sPod)
	if err != nil {
		t.Fatal(err)
	}

	if !w.Equals(&expectedWorkload) {
		t.Errorf("Workload got %+v want %+v", w, expectedWorkload)
	}
}

func TestGetWorkloadFromModel(t *testing.T) {
	expectedWorkload := Workload{
		Name:      "foo",
		Namespace: "foo",
		Kind:      "Deployment",
	}

	ciliumEndpoint := cilium_v2.CiliumEndpoint{
		TypeMeta: v1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:         "foo-xxddxx",
			GenerateName: "foo-",
			Namespace:    "foo",
			Labels: map[string]string{
				"foo":  "xxddxx",
				"foo1": "xdx",
			},
		},
		Status: cilium_v2.EndpointStatus{Workload: &models.Workload{
			Name:      "foo",
			Namespace: "foo",
			Kind:      "Deployment",
		}},
	}
	w := GetWorkloadFromModel(ciliumEndpoint.Status.Workload)

	if !w.Equals(&expectedWorkload) {
		t.Errorf("Workload got %+v want %+v", w, expectedWorkload)
	}
}

func TestDeploymentMetadata(t *testing.T) {
	controller := true
	tests := map[string]struct {
		name         string
		pod          *slim_corev1.Pod
		wantWorkload *Workload
		expectOK     bool
	}{
		"deployment-test1": {
			name: "deployment-name-deploy",
			pod:  podForDeployment("deploy", "12345", "default"),
			wantWorkload: &Workload{
				Name:      "deploy",
				Kind:      "Deployment",
				Namespace: "default",
			},
			expectOK: true,
		},
		"deployment-test2": {
			name: "deployment-name-deploy2",
			pod:  podForDeployment("deploy2", "45678", "default"),
			wantWorkload: &Workload{
				Name:      "deploy2",
				Kind:      "Deployment",
				Namespace: "default",
			},
			expectOK: true,
		},
		"deployment-test3": {
			name: "non-deployment",
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:         "replicaset0-abcd0",
					GenerateName: "replicaset0-",
					Namespace:    "default",
					OwnerReferences: []slim_metav1.OwnerReference{{
						Controller: &controller,
						Kind:       "ReplicaSet",
						Name:       "replicaset0",
					}},
				},
			},
			wantWorkload: &Workload{
				Name:      "replicaset0",
				Kind:      "ReplicaSet",
				Namespace: "default",
			},
			expectOK: true,
		},
		"deployment-test4": {
			name: "bare-pod",
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "some-pod",
				},
			},
			expectOK: false,
		},
	}

	for n, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload, err := GetWorkloadDataFromPod(tt.pod)
			if tt.expectOK != (err == nil) {
				t.Fatalf("Test case %s failed, expected ok=%t, got ok=%t, return err shows %s", n, tt.expectOK, err == nil, err.Error())
			}
			if err == nil {
				if !workload.Equals(tt.wantWorkload) {
					t.Errorf("Test case %s failed, workload got %+v want %+v", n, workload, tt.wantWorkload)
				}
			}
		})
	}
}

func podForDeployment(deploymentName string, hash string, namespace string) *slim_corev1.Pod {
	controller := true
	labels := make(map[string]string)
	if hash != "" {
		labels["pod-template-hash"] = hash
	}
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:         deploymentName + "-" + hash + "-" + "asdf0",
			GenerateName: deploymentName + "-" + hash + "-",
			Namespace:    namespace,
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
	tests := map[string]struct {
		name         string
		jobName      string
		wantWorkload *Workload
	}{
		"cron-job-test1": {
			name:    "cron-job-name-sec",
			jobName: "sec-1234567890",
			wantWorkload: &Workload{
				Name:      "sec",
				Kind:      "CronJob",
				Namespace: "default",
			},
		},
		"cron-job-test2": {
			name:    "cron-job-name-min",
			jobName: "min-12345678",
			wantWorkload: &Workload{
				Name:      "min",
				Kind:      "CronJob",
				Namespace: "default",
			},
		},
		"cron-job-test3": {
			name:    "non-cron-job-name",
			jobName: "job-123",
			wantWorkload: &Workload{
				Name:      "job-123",
				Kind:      "Job",
				Namespace: "default",
			},
		},
	}

	for n, tt := range tests {
		controller := true
		t.Run(tt.name, func(t *testing.T) {
			workload, err := GetWorkloadDataFromPod(
				&slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						GenerateName: tt.jobName + "-pod",
						Namespace:    "default",
						OwnerReferences: []slim_metav1.OwnerReference{{
							Controller: &controller,
							Kind:       "Job",
							Name:       tt.jobName,
						}},
					},
				},
			)
			if err != nil {
				t.Fatalf("Test case %s failed, expected err=nil, got err=%s", n, err.Error())
			} else {
				if !workload.Equals(tt.wantWorkload) {
					t.Errorf("Test case %s failed, workload got %+v want %+v", n, workload, tt.wantWorkload)
				}
			}
		})
	}
}

func TestDeploymentConfigMetadata(t *testing.T) {
	tests := map[string]struct {
		name         string
		pod          *slim_corev1.Pod
		wantWorkload *Workload
	}{
		"deploymentconfig-test1": {
			name: "deployconfig-name-deploy",
			pod:  podForDeploymentConfig("deploy", true),
			wantWorkload: &Workload{
				Name:      "deploy",
				Kind:      "DeploymentConfig",
				Namespace: "default",
			},
		},
		"deploymentconfig-test2": {
			name: "deployconfig-name-deploy2",
			pod:  podForDeploymentConfig("deploy2", true),
			wantWorkload: &Workload{
				Name:      "deploy2",
				Kind:      "DeploymentConfig",
				Namespace: "default",
			},
		},
		"deploymentconfig-test3": {
			name: "non-deployconfig-label",
			pod:  podForDeploymentConfig("dep", false),
			wantWorkload: &Workload{
				Name:      "dep-rc",
				Kind:      "ReplicationController",
				Namespace: "default",
			},
		},
	}

	for n, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload, err := GetWorkloadDataFromPod(tt.pod)
			if err != nil {
				t.Fatalf("Test case %s failed, expected err=nil, got err=%s", n, err.Error())
			} else {
				if !workload.Equals(tt.wantWorkload) {
					t.Errorf("Test case %s failed, workload got %+v want %+v", n, workload, tt.wantWorkload)
				}
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
			Namespace:    "default",
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
	tests := map[string]struct {
		name            string
		statefulsetName string
		wantWorkload    *Workload
	}{
		"statefulset-test1": {
			name:            "statefulset-name-foo",
			statefulsetName: "foo",
			wantWorkload: &Workload{
				Name:      "foo",
				Namespace: "default",
				Kind:      "StatefulSet",
			},
		},
	}

	for n, tt := range tests {
		controller := true
		t.Run(tt.name, func(t *testing.T) {
			workload, err := GetWorkloadDataFromPod(
				&slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						GenerateName: tt.statefulsetName + "-",
						Namespace:    "default",
						OwnerReferences: []slim_metav1.OwnerReference{{
							Controller: &controller,
							Kind:       "StatefulSet",
							Name:       tt.statefulsetName,
						}},
					},
				},
			)
			if err != nil {
				t.Fatalf("Test case %s failed, expected ok=nil, got err=%s", n, err.Error())
			} else {
				if !workload.Equals(tt.wantWorkload) {
					t.Errorf("Test case %s failed, workload got %+v want %+v", n, workload, tt.wantWorkload)
				}
			}
		})
	}
}
