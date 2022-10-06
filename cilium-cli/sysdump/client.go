// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"bytes"
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"

	"github.com/cilium/cilium-cli/k8s"
)

type KubernetesClient interface {
	AutodetectFlavor(ctx context.Context) k8s.Flavor
	CopyFromPod(ctx context.Context, namespace, pod, container string, fromFile, destFile string) error
	CreateEphemeralContainer(ctx context.Context, pod *corev1.Pod, ec *corev1.EphemeralContainer) (*corev1.Pod, error)
	CreatePod(ctx context.Context, namespace string, pod *corev1.Pod, opts metav1.CreateOptions) (*corev1.Pod, error)
	GetPod(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Pod, error)
	DeletePod(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	GetLogs(ctx context.Context, namespace, name, container string, sinceTime time.Time, limitBytes int64, previous bool) (string, error)
	GetPodsTable(ctx context.Context) (*metav1.Table, error)
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	GetVersion(ctx context.Context) (string, error)
	ListCiliumClusterwideNetworkPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error)
	ListCiliumClusterwideEnvoyConfigs(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideEnvoyConfigList, error)
	ListCiliumIdentities(ctx context.Context) (*ciliumv2.CiliumIdentityList, error)
	ListCiliumEgressNATPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumEgressNATPolicyList, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	ListCiliumEnvoyConfigs(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEnvoyConfigList, error)
	ListCiliumLocalRedirectPolicies(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumLocalRedirectPolicyList, error)
	ListCiliumNetworkPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumNetworkPolicyList, error)
	ListCiliumNodes(ctx context.Context) (*ciliumv2.CiliumNodeList, error)
	ListDaemonSet(ctx context.Context, namespace string, o metav1.ListOptions) (*appsv1.DaemonSetList, error)
	ListEvents(ctx context.Context, o metav1.ListOptions) (*corev1.EventList, error)
	ListEndpoints(ctx context.Context, o metav1.ListOptions) (*corev1.EndpointsList, error)
	ListIngresses(ctx context.Context, o metav1.ListOptions) (*networkingv1.IngressList, error)
	ListNamespaces(ctx context.Context, o metav1.ListOptions) (*corev1.NamespaceList, error)
	ListNetworkPolicies(ctx context.Context, o metav1.ListOptions) (*networkingv1.NetworkPolicyList, error)
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	ListServices(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.ServiceList, error)
	ListUnstructured(ctx context.Context, gvr schema.GroupVersionResource, namespace *string, o metav1.ListOptions) (*unstructured.UnstructuredList, error)
}
