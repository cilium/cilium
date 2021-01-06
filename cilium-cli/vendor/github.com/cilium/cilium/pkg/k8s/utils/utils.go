// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"sort"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/option"

	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ServiceProxyNameLabel is the label for service proxy name in k8s service related
	// objects.
	serviceProxyNameLabel = "service.kubernetes.io/service-proxy-name"
)

type NamespaceNameGetter interface {
	GetNamespace() string
	GetName() string
}

// ExtractNamespace extracts the namespace of ObjectMeta.
// For cluster scoped objects the Namespace field is empty and this function
// assumes that the object is returned from kubernetes itself implying that
// the namespace is empty only and only when the Object is cluster scoped
// and thus returns empty namespace for such objects.
func ExtractNamespace(np NamespaceNameGetter) string {
	return np.GetNamespace()
}

// ExtractNamespaceOrDefault extracts the namespace of ObjectMeta, it returns default
// namespace if the namespace field in the ObjectMeta is empty.
func ExtractNamespaceOrDefault(np NamespaceNameGetter) string {
	ns := np.GetNamespace()
	if ns == "" {
		return v1.NamespaceDefault
	}

	return ns
}

// GetObjNamespaceName returns the object's namespace and name.
// If the object is cluster scoped then the function returns only the object name
// without any namespace prefix.
func GetObjNamespaceName(obj NamespaceNameGetter) string {
	ns := ExtractNamespace(obj)
	if ns == "" {
		return obj.GetName()
	}

	return ns + "/" + obj.GetName()
}

// GetServiceListOptionsModifier returns the options modifier for service object list.
// This methods returns a ListOptions modifier which adds a label selector to only
// select services that are in context of Cilium.
// Like kube-proxy Cilium does not select services containing k8s headless service label.
// We honor service.kubernetes.io/service-proxy-name label in the service object and only
// handle services that match our service proxy name. If the service proxy name for Cilium
// is an empty string, we assume that Cilium is the default service handler in which case
// we select all services that don't have the above mentioned label.
func GetServiceListOptionsModifier() (func(options *v1meta.ListOptions), error) {
	var (
		serviceNameSelector, nonHeadlessServiceSelector *labels.Requirement
		err                                             error
	)

	nonHeadlessServiceSelector, err = labels.NewRequirement(v1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		return nil, err
	}

	if option.Config.K8sServiceProxyName == "" {
		serviceNameSelector, err = labels.NewRequirement(
			serviceProxyNameLabel, selection.DoesNotExist, nil)
	} else {
		serviceNameSelector, err = labels.NewRequirement(
			serviceProxyNameLabel, selection.DoubleEquals, []string{option.Config.K8sServiceProxyName})
	}

	if err != nil {
		return nil, err
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*serviceNameSelector, *nonHeadlessServiceSelector)

	return func(options *v1meta.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}, nil
}

// GetLatestPodReadiness returns the lastest podReady condition on a given pod.
func GetLatestPodReadiness(podStatus slim_corev1.PodStatus) slim_corev1.ConditionStatus {
	for _, cond := range podStatus.Conditions {
		if cond.Type == slim_corev1.PodReady {
			return cond.Status
		}
	}
	return slim_corev1.ConditionUnknown
}

// ValidIPs return a sorted slice of unique IP addresses retrieved from the given PodStatus.
// Returns an error when no IPs are found.
func ValidIPs(podStatus slim_corev1.PodStatus) []string {
	if len(podStatus.PodIPs) == 0 && len(podStatus.PodIP) == 0 {
		return nil
	}

	// make it a set first to avoid repeated IP addresses
	ipsMap := make(map[string]struct{}, 1+len(podStatus.PodIPs))
	if podStatus.PodIP != "" {
		ipsMap[podStatus.PodIP] = struct{}{}
	}
	for _, podIP := range podStatus.PodIPs {
		if podIP.IP != "" {
			ipsMap[podIP.IP] = struct{}{}
		}
	}

	ips := make([]string, 0, len(ipsMap))
	for ipStr := range ipsMap {
		ips = append(ips, ipStr)
	}
	sort.Strings(ips)
	return ips
}

// IsPodRunning returns true if the pod is considered to be in running state.
// We consider a Running pod a pod that does not report a Failed nor a Succeeded
// pod Phase.
func IsPodRunning(status slim_corev1.PodStatus) bool {
	switch status.Phase {
	case slim_corev1.PodFailed, slim_corev1.PodSucceeded:
		return false
	}
	return true
}
