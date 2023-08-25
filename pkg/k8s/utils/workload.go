// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright Istio Authors
// Copyright Authors of Hubble

// GetWorkloadMetaFromPod and cronJobNameRegexp are copied from
// https://github.com/istio/istio/blob/1aca7a67afd7b3e1d24fafb2fbfbeaf1e41534c0/pkg/kube/util.go
//
// Modifications:
// GetDeployMetaFromPod has been renamed to GetWorkloadMetaFromPod and has
// been updated to use the cilium slim API types.
// We do not store the APIVersion of the owning workload in the TypeMeta
// either, because it isn't needed for our purposes, and our slim types do not
// have this field.
// We fallback to the pod's ownerReference if we cannot find a more suitable
// workload based on heuristics, whereas the original code defaulted to the
// pod's name. This may be the case when using ReplicaSets without a Deployment.

package utils

import (
	"regexp"
	"strings"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

// GetWorkloadMetaFromPod heuristically derives workload metadata from the pod spec.
func GetWorkloadMetaFromPod(pod *slim_corev1.Pod) (slim_metav1.ObjectMeta, slim_metav1.TypeMeta, bool) {
	if pod == nil {
		return slim_metav1.ObjectMeta{}, slim_metav1.TypeMeta{}, false
	}
	// try to capture more useful namespace/name info for deployments, etc.
	// TODO(dougreid): expand to enable lookup of OWNERs recursively a la kubernetesenv
	workloadObjectMeta := pod.ObjectMeta
	workloadObjectMeta.OwnerReferences = nil

	var ok bool
	var typeMetadata slim_metav1.TypeMeta
	if len(pod.GenerateName) > 0 {
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
		if controllerFound {
			ok = true
			// default to the owner kind/name
			typeMetadata.Kind = controllerRef.Kind
			workloadObjectMeta.Name = controllerRef.Name

			// heuristic for deployment detection
			if typeMetadata.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] != "" && strings.HasSuffix(controllerRef.Name, pod.Labels["pod-template-hash"]) {
				name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["pod-template-hash"])
				workloadObjectMeta.Name = name
				typeMetadata.Kind = "Deployment"
			} else if typeMetadata.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] == "" {
				workloadObjectMeta.Name = controllerRef.Name
				typeMetadata.Kind = "ReplicaSet"
			} else if typeMetadata.Kind == "ReplicationController" && pod.Labels["deploymentconfig"] != "" {
				// If the pod is controlled by the replication controller, which is created by the DeploymentConfig resource in
				// Openshift platform, set the deploy name to the deployment config's name, and the kind to 'DeploymentConfig'.
				//
				// nolint: lll
				// For DeploymentConfig details, refer to
				// https://docs.openshift.com/container-platform/4.1/applications/deployments/what-deployments-are.html#deployments-and-deploymentconfigs_what-deployments-are
				//
				// For the reference to the pod label 'deploymentconfig', refer to
				// https://github.com/openshift/library-go/blob/7a65fdb398e28782ee1650959a5e0419121e97ae/pkg/apps/appsutil/const.go#L25
				workloadObjectMeta.Name = pod.Labels["deploymentconfig"]
				typeMetadata.Kind = "DeploymentConfig"
				delete(workloadObjectMeta.Labels, "deploymentconfig")
			} else if typeMetadata.Kind == "Job" {
				// If job name suffixed with `-<digit-timestamp>`, where the length of digit timestamp is 8~10,
				// trim the suffix and set kind to cron job.
				if jn := cronJobNameRegexp.FindStringSubmatch(controllerRef.Name); len(jn) == 2 {
					workloadObjectMeta.Name = jn[1]
					typeMetadata.Kind = "CronJob"
				}
			}
		}
	}

	return workloadObjectMeta, typeMetadata, ok
}
