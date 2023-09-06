// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"github.com/cilium/cilium/api/v1/models"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"regexp"
	"strings"
)

var (
	cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)
)

// Workload Kubernetes pod’s workload info (workloads are: Deployment, Statefulset, Daemonset, ReplicationController, CronJob, Job, DeploymentConfig (OpenShift), etc).
type Workload struct {
	Name      string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,3,opt,name=namespace"`
	Kind      string `json:"kind,omitempty" protobuf:"bytes,1,opt,name=kind"`
}

// Equals compare two workload is equal
func (w *Workload) Equals(o *Workload) bool {
	if w == o {
		return true
	}
	if w == nil || o == nil {
		return false
	}
	return w.Name == o.Name && w.Namespace == o.Namespace && w.Kind == o.Kind
}

// GetWorkloadFromModel  convert models.Workload to this workload struct
func GetWorkloadFromModel(workload *models.Workload) *Workload {
	if workload == nil {
		return nil
	}
	return &Workload{
		Name:      workload.Name,
		Namespace: workload.Namespace,
		Kind:      workload.Kind,
	}
}

// GetWorkloadDataFromPod GetWorkloadMetaFromPod and cronJobNameRegexp are copied from
// https://github.com/istio/istio/blob/1aca7a67afd7b3e1d24fafb2fbfbeaf1e41534c0/pkg/kube/util.go
//
// Modifications:
// This code has been modified and move to this file from k8s/utils/workload.go
// main changes are store the workload data in workload struct instead of slim_metav1.ObjectMeta and slim_metav1.TypeMeta
// Below is the original comment in k8s/utils/workload.go:
// GetDeployMetaFromPod has been renamed to GetWorkloadMetaFromPod and has
// been updated to use the cilium slim API types.
// We do not store the APIVersion of the owning workload in the TypeMeta
// either, because it isn't needed for our purposes, and our slim types do not
// have this field.
// We fallback to the pod's ownerReference if we cannot find a more suitable
// workload based on heuristics, whereas the original code defaulted to the
// pod's name. This may be the case when using ReplicaSets without a Deployment.
func GetWorkloadDataFromPod(pod *slim_corev1.Pod) (*Workload, error) {
	if pod == nil {
		return nil, fmt.Errorf("pod is nil")
	}
	if len(pod.GenerateName) == 0 {
		return nil, fmt.Errorf("pod generatename is empty, ignoring")
	}
	// try to capture more useful namespace/name info for deployments, etc.
	// TODO(dougreid): expand to enable lookup of OWNERs recursively a la kubernetesenv

	// if the pod name was generated (or is scheduled for generation), we can begin an investigation into the controlling reference for the pod.
	var controllerRef slim_metav1.OwnerReference
	controllerFound := false
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			controllerRef = ref
			controllerFound = true
			break
		}
	}

	if !controllerFound {
		return nil, fmt.Errorf("pod controller not found")
	}

	// default to the owner kind/name
	workload := &Workload{
		Name:      controllerRef.Name,
		Namespace: pod.Namespace,
		Kind:      controllerRef.Kind,
	}

	// heuristic for deployment detection
	if workload.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] != "" && strings.HasSuffix(controllerRef.Name, pod.Labels["pod-template-hash"]) {
		name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["pod-template-hash"])
		workload.Name = name
		workload.Kind = "Deployment"
		return workload, nil
	} else if workload.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] == "" {
		workload.Name = controllerRef.Name
		workload.Kind = "ReplicaSet"
		return workload, nil
	} else if workload.Kind == "ReplicationController" && pod.Labels["deploymentconfig"] != "" {
		// If the pod is controlled by the replication controller, which is created by the DeploymentConfig resource in
		// Openshift platform, set the deploy name to the deployment config's name, and the kind to 'DeploymentConfig'.
		//
		// nolint: lll
		// For DeploymentConfig details, refer to
		// https://docs.openshift.com/container-platform/4.1/applications/deployments/what-deployments-are.html#deployments-and-deploymentconfigs_what-deployments-are
		//
		// For the reference to the pod label 'deploymentconfig', refer to
		// https://github.com/openshift/library-go/blob/7a65fdb398e28782ee1650959a5e0419121e97ae/pkg/apps/appsutil/const.go#L25
		workload.Name = pod.Labels["deploymentconfig"]
		workload.Kind = "DeploymentConfig"
		return workload, nil
	} else if workload.Kind == "Job" {
		// If job name suffixed with `-<digit-timestamp>`, where the length of digit timestamp is 8~10,
		// trim the suffix and set kind to cron job.
		if jn := cronJobNameRegexp.FindStringSubmatch(controllerRef.Name); len(jn) == 2 {
			workload.Name = jn[1]
			workload.Kind = "CronJob"
			return workload, nil
		}
	}
	return workload, nil
}
