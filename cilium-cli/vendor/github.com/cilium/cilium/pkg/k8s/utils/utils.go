// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"net"
	"sort"
	"strings"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/ip"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	labelsPkg "github.com/cilium/cilium/pkg/labels"
)

const (
	// ServiceProxyNameLabel is the label for service proxy name in k8s service related
	// objects.
	serviceProxyNameLabel = "service.kubernetes.io/service-proxy-name"
	// EndpointSliceMeshControllerName is a unique value used with LabelManagedBy to indicate
	// the component managing an EndpointSlice.
	EndpointSliceMeshControllerName = "endpointslice-mesh-controller.cilium.io"
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

// PolicyConfiguration is the required configuration for K8s NetworkPolicy
type PolicyConfiguration interface {
	// K8sNetworkPolicyEnabled returns true if cilium agent needs to support K8s NetworkPolicy
	K8sNetworkPolicyEnabled() bool
}

// GetEndpointSliceListOptionsModifier returns the options modifier for endpointSlice object list.
// This methods returns a ListOptions modifier which adds a label selector to
// select all endpointSlice objects they are not from remote clusters in Cilium cluster mesh.
// This is mostly the same behavior as kube-proxy except the cluster mesh behavior which is
// tied to how Cilium internally works with clustermesh endpoints and that this function also doesn't ignore headless Services.
// Given label mirroring from the service objects to endpoint slice objects were introduced in Kubernetes PR 94443,
// and released as part of Kubernetes v1.20; we can start using GetServiceAndEndpointListOptionsModifier for
// endpoint slices when dropping support for Kubernetes v1.19 and older. We can do that since the
// serviceProxyNameLabel label will then be mirrored to endpoint slices for services with that label.
// We also ignore Kubernetes endpoints coming from other clusters in the Cilium clustermesh here as
// Cilium does not rely on mirrored Kubernetes EndpointSlice for any of its functionalities.
func GetEndpointSliceListOptionsModifier() (func(options *v1meta.ListOptions), error) {
	nonRemoteEndpointSelector, err := labels.NewRequirement(discoveryv1.LabelManagedBy, selection.NotEquals, []string{EndpointSliceMeshControllerName})
	if err != nil {
		return nil, err
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*nonRemoteEndpointSelector)

	return func(options *v1meta.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}, nil
}

// GetServiceAndEndpointListOptionsModifier returns the options modifier for service and endpoint object lists.
// This methods returns a ListOptions modifier which adds a label selector to only
// select services that are in context of Cilium.
// Unlike kube-proxy Cilium does not select services/endpoints containing k8s headless service label.
// We honor service.kubernetes.io/service-proxy-name label in the service object and only
// handle services that match our service proxy name. If the service proxy name for Cilium
// is an empty string, we assume that Cilium is the default service handler in which case
// we select all services that don't have the above mentioned label.
func GetServiceAndEndpointListOptionsModifier(k8sServiceProxy string) (func(options *v1meta.ListOptions), error) {
	var (
		serviceNameSelector *labels.Requirement
		err                 error
	)

	if k8sServiceProxy == "" {
		serviceNameSelector, err = labels.NewRequirement(
			serviceProxyNameLabel, selection.DoesNotExist, nil)
	} else {
		serviceNameSelector, err = labels.NewRequirement(
			serviceProxyNameLabel, selection.DoubleEquals, []string{k8sServiceProxy})
	}

	if err != nil {
		return nil, err
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*serviceNameSelector)

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

// GetClusterIPByFamily returns a service clusterip by family.
// From - https://github.com/kubernetes/kubernetes/blob/release-1.20/pkg/proxy/util/utils.go#L386-L411
func GetClusterIPByFamily(ipFamily slim_corev1.IPFamily, service *slim_corev1.Service) string {
	// allowing skew
	if len(service.Spec.IPFamilies) == 0 {
		if len(service.Spec.ClusterIP) == 0 || service.Spec.ClusterIP == v1.ClusterIPNone {
			return ""
		}

		IsIPv6Family := (ipFamily == slim_corev1.IPv6Protocol)
		if IsIPv6Family == ip.IsIPv6(net.ParseIP(service.Spec.ClusterIP)) {
			return service.Spec.ClusterIP
		}

		return ""
	}

	for idx, family := range service.Spec.IPFamilies {
		if family == ipFamily {
			if idx < len(service.Spec.ClusterIPs) {
				return service.Spec.ClusterIPs[idx]
			}
		}
	}

	return ""
}

// nameLabelsGetter is an interface that returns the name and the labels for
// the namespace.
type nameLabelsGetter interface {
	GetName() string
	GetLabels() map[string]string
}

// filterPodLabels returns a copy of the given labels map, without the labels owned by Cilium.
func filterPodLabels(labels map[string]string) map[string]string {
	res := map[string]string{}
	for k, v := range labels {
		if strings.HasPrefix(k, k8sconst.LabelPrefix) {
			continue
		}
		res[k] = v
	}
	return res
}

// SanitizePodLabels makes sure that no important pod labels were overridden manually on k8s pod
// object creation.
func SanitizePodLabels(podLabels map[string]string, namespace nameLabelsGetter, serviceAccount, clusterName string) map[string]string {
	sanitizedLabels := filterPodLabels(podLabels)

	// Sanitize namespace labels
	for k, v := range namespace.GetLabels() {
		sanitizedLabels[joinPath(k8sconst.PodNamespaceMetaLabels, k)] = v
	}
	// Sanitize namespace name label
	sanitizedLabels[k8sconst.PodNamespaceLabel] = namespace.GetName()
	// Sanitize service account name
	if serviceAccount != "" {
		sanitizedLabels[k8sconst.PolicyLabelServiceAccount] = serviceAccount
	} else {
		delete(sanitizedLabels, k8sconst.PolicyLabelServiceAccount)
	}
	// Sanitize cluster name
	sanitizedLabels[k8sconst.PolicyLabelCluster] = clusterName

	return sanitizedLabels
}

// StripPodSpecialLabels strips labels that are not supposed to be coming from a k8s pod object update.
func StripPodSpecialLabels(labels map[string]string) map[string]string {
	sanitizedLabels := make(map[string]string)
	for k, v := range filterPodLabels(labels) {
		// If the key contains the prefix for namespace labels then we will
		// ignore it.
		if strings.HasPrefix(k, k8sconst.PodNamespaceMetaLabels) {
			continue
		}
		// Also ignore it if the key is a kubernetes namespace label.
		if k == k8sconst.PodNamespaceLabel {
			continue
		}
		sanitizedLabels[k] = v
	}
	return sanitizedLabels
}

// joinPath mimics JoinPath from pkg/policy/utils, which could not be imported here due to circular dependency
func joinPath(a, b string) string {
	return a + labelsPkg.PathDelimiter + b
}
