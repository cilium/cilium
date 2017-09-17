/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package preemption

import (
	"fmt"
	"math"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/tools/record"
	v1qos "k8s.io/kubernetes/pkg/api/v1/helper/qos"
	"k8s.io/kubernetes/pkg/api/v1/resource"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/kubelet/eviction"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	"k8s.io/kubernetes/plugin/pkg/scheduler/algorithm"
	"k8s.io/kubernetes/plugin/pkg/scheduler/algorithm/predicates"
)

const message = "Preempted in order to admit critical pod"

// CriticalPodAdmissionFailureHandler is an AdmissionFailureHandler that handles admission failure for Critical Pods.
// If the ONLY admission failures are due to insufficient resources, then CriticalPodAdmissionHandler evicts pods
// so that the critical pod can be admitted.  For evictions, the CriticalPodAdmissionHandler evicts a set of pods that
// frees up the required resource requests.  The set of pods is designed to minimize impact, and is prioritized according to the ordering:
// minimal impact for guaranteed pods > minimal impact for burstable pods > minimal impact for besteffort pods.
// minimal impact is defined as follows: fewest pods evicted > fewest total requests of pods.
// finding the fewest total requests of pods is considered besteffort.
type CriticalPodAdmissionHandler struct {
	getPodsFunc eviction.ActivePodsFunc
	killPodFunc eviction.KillPodFunc
	recorder    record.EventRecorder
}

var _ lifecycle.AdmissionFailureHandler = &CriticalPodAdmissionHandler{}

func NewCriticalPodAdmissionHandler(getPodsFunc eviction.ActivePodsFunc, killPodFunc eviction.KillPodFunc, recorder record.EventRecorder) *CriticalPodAdmissionHandler {
	return &CriticalPodAdmissionHandler{
		getPodsFunc: getPodsFunc,
		killPodFunc: killPodFunc,
		recorder:    recorder,
	}
}

// HandleAdmissionFailure gracefully handles admission rejection, and, in some cases,
// to allow admission of the pod despite its previous failure.
func (c *CriticalPodAdmissionHandler) HandleAdmissionFailure(pod *v1.Pod, failureReasons []algorithm.PredicateFailureReason) (bool, []algorithm.PredicateFailureReason, error) {
	if !kubetypes.IsCriticalPod(pod) || !utilfeature.DefaultFeatureGate.Enabled(features.ExperimentalCriticalPodAnnotation) {
		return false, failureReasons, nil
	}
	// InsufficientResourceError is not a reason to reject a critical pod.
	// Instead of rejecting, we free up resources to admit it, if no other reasons for rejection exist.
	nonResourceReasons := []algorithm.PredicateFailureReason{}
	resourceReasons := []*admissionRequirement{}
	for _, reason := range failureReasons {
		if r, ok := reason.(*predicates.InsufficientResourceError); ok {
			resourceReasons = append(resourceReasons, &admissionRequirement{
				resourceName: r.ResourceName,
				quantity:     r.GetInsufficientAmount(),
			})
		} else {
			nonResourceReasons = append(nonResourceReasons, reason)
		}
	}
	if len(nonResourceReasons) > 0 {
		// Return only reasons that are not resource related, since critical pods cannot fail admission for resource reasons.
		return false, nonResourceReasons, nil
	}
	err := c.evictPodsToFreeRequests(admissionRequirementList(resourceReasons))
	// if no error is returned, preemption succeeded and the pod is safe to admit.
	return err == nil, nil, err
}

// freeRequests takes a list of insufficient resources, and attempts to free them by evicting pods
// based on requests.  For example, if the only insufficient resource is 200Mb of memory, this function could
// evict a pod with request=250Mb.
func (c *CriticalPodAdmissionHandler) evictPodsToFreeRequests(insufficientResources admissionRequirementList) error {
	podsToPreempt, err := getPodsToPreempt(c.getPodsFunc(), insufficientResources)
	if err != nil {
		return fmt.Errorf("preemption: error finding a set of pods to preempt: %v", err)
	}
	glog.Infof("preemption: attempting to evict pods %v, in order to free up resources: %s", podsToPreempt, insufficientResources.toString())
	for _, pod := range podsToPreempt {
		status := v1.PodStatus{
			Phase:   v1.PodFailed,
			Message: message,
			Reason:  events.PreemptContainer,
		}
		// record that we are evicting the pod
		c.recorder.Eventf(pod, v1.EventTypeWarning, events.PreemptContainer, message)
		// this is a blocking call and should only return when the pod and its containers are killed.
		err := c.killPodFunc(pod, status, nil)
		if err != nil {
			return fmt.Errorf("preemption: pod %s failed to evict %v", format.Pod(pod), err)
		}
		glog.Infof("preemption: pod %s evicted successfully", format.Pod(pod))
	}
	return nil
}

// getPodsToPreempt returns a list of pods that could be preempted to free requests >= requirements
func getPodsToPreempt(pods []*v1.Pod, requirements admissionRequirementList) ([]*v1.Pod, error) {
	bestEffortPods, burstablePods, guaranteedPods := sortPodsByQOS(pods)

	// make sure that pods exist to reclaim the requirements
	unableToMeetRequirements := requirements.subtract(append(append(bestEffortPods, burstablePods...), guaranteedPods...)...)
	if len(unableToMeetRequirements) > 0 {
		return nil, fmt.Errorf("no set of running pods found to reclaim resources: %v", unableToMeetRequirements.toString())
	}
	// find the guaranteed pods we would need to evict if we already evicted ALL burstable and besteffort pods.
	guarateedToEvict, err := getPodsToPreemptByDistance(guaranteedPods, requirements.subtract(append(bestEffortPods, burstablePods...)...))
	if err != nil {
		return nil, err
	}
	// Find the burstable pods we would need to evict if we already evicted ALL besteffort pods, and the required guaranteed pods.
	burstableToEvict, err := getPodsToPreemptByDistance(burstablePods, requirements.subtract(append(bestEffortPods, guarateedToEvict...)...))
	if err != nil {
		return nil, err
	}
	// Find the besteffort pods we would need to evict if we already evicted the required guaranteed and burstable pods.
	bestEffortToEvict, err := getPodsToPreemptByDistance(bestEffortPods, requirements.subtract(append(burstableToEvict, guarateedToEvict...)...))
	if err != nil {
		return nil, err
	}
	return append(append(bestEffortToEvict, burstableToEvict...), guarateedToEvict...), nil
}

// finds the pods that have pod requests >= admission requirements.
// Chooses pods that minimize "distance" to the requirements.
// If more than one pod exists that fulfills the remaining requirements,
// it chooses the pod that has the "smaller resource request"
// This method, by repeatedly choosing the pod that fulfills as much of the requirements as possible,
// attempts to minimize the number of pods returned.
func getPodsToPreemptByDistance(pods []*v1.Pod, requirements admissionRequirementList) ([]*v1.Pod, error) {
	podsToEvict := []*v1.Pod{}
	// evict pods by shortest distance from remaining requirements, updating requirements every round.
	for len(requirements) > 0 {
		if len(pods) == 0 {
			return nil, fmt.Errorf("no set of running pods found to reclaim resources: %v", requirements.toString())
		}
		// all distances must be less than len(requirements), because the max distance for a single requirement is 1
		bestDistance := float64(len(requirements) + 1)
		bestPodIndex := 0
		// Find the pod with the smallest distance from requirements
		// Or, in the case of two equidistant pods, find the pod with "smaller" resource requests.
		for i, pod := range pods {
			dist := requirements.distance(pod)
			if dist < bestDistance || (bestDistance == dist && smallerResourceRequest(pod, pods[bestPodIndex])) {
				bestDistance = dist
				bestPodIndex = i
			}
		}
		// subtract the pod from requirements, and transfer the pod from input-pods to pods-to-evicted
		requirements = requirements.subtract(pods[bestPodIndex])
		podsToEvict = append(podsToEvict, pods[bestPodIndex])
		pods[bestPodIndex] = pods[len(pods)-1]
		pods = pods[:len(pods)-1]
	}
	return podsToEvict, nil
}

type admissionRequirement struct {
	resourceName v1.ResourceName
	quantity     int64
}

type admissionRequirementList []*admissionRequirement

// distance of the pods requests from the admissionRequirements.
// distance is measured by the fraction of the requirement satisfied by the pod,
// so that each requirement is weighted equally, regardless of absolute magnitude.
func (a admissionRequirementList) distance(pod *v1.Pod) float64 {
	dist := float64(0)
	for _, req := range a {
		remainingRequest := float64(req.quantity - resource.GetResourceRequest(pod, req.resourceName))
		if remainingRequest < 0 {
			remainingRequest = 0
		}
		dist += math.Pow(remainingRequest/float64(req.quantity), 2)
	}
	return dist
}

// returns a new admissionRequirementList containing remaining requirements if the provided pod
// were to be preempted
func (a admissionRequirementList) subtract(pods ...*v1.Pod) admissionRequirementList {
	newList := []*admissionRequirement{}
	for _, req := range a {
		newQuantity := req.quantity
		for _, pod := range pods {
			newQuantity -= resource.GetResourceRequest(pod, req.resourceName)
		}
		if newQuantity > 0 {
			newList = append(newList, &admissionRequirement{
				resourceName: req.resourceName,
				quantity:     newQuantity,
			})
		}
	}
	return newList
}

func (a admissionRequirementList) toString() string {
	s := "["
	for _, req := range a {
		s += fmt.Sprintf("(res: %v, q: %d), ", req.resourceName, req.quantity)
	}
	return s + "]"
}

// returns lists containing non-critical besteffort, burstable, and guaranteed pods
func sortPodsByQOS(pods []*v1.Pod) (bestEffort, burstable, guaranteed []*v1.Pod) {
	for _, pod := range pods {
		if !kubetypes.IsCriticalPod(pod) {
			switch v1qos.GetPodQOS(pod) {
			case v1.PodQOSBestEffort:
				bestEffort = append(bestEffort, pod)
			case v1.PodQOSBurstable:
				burstable = append(burstable, pod)
			case v1.PodQOSGuaranteed:
				guaranteed = append(guaranteed, pod)
			default:
			}
		}
	}
	return
}

// returns true if pod1 has a smaller request than pod2
func smallerResourceRequest(pod1 *v1.Pod, pod2 *v1.Pod) bool {
	priorityList := []v1.ResourceName{
		v1.ResourceNvidiaGPU,
		v1.ResourceMemory,
		v1.ResourceCPU,
	}
	for _, res := range priorityList {
		req1 := resource.GetResourceRequest(pod1, res)
		req2 := resource.GetResourceRequest(pod2, res)
		if req1 < req2 {
			return true
		} else if req1 > req2 {
			return false
		}
	}
	return true
}
