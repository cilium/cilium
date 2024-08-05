// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"bytes"
	"context"
	"io"

	"github.com/blang/semver/v4"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/cilium-cli/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type KubernetesClient interface {
	AutodetectFlavor(ctx context.Context) k8s.Flavor
	CopyFromPod(ctx context.Context, namespace, pod, container, fromFile, destFile string, retryLimit int) error
	CreateEphemeralContainer(ctx context.Context, pod *corev1.Pod, ec *corev1.EphemeralContainer) (*corev1.Pod, error)
	CreatePod(ctx context.Context, namespace string, pod *corev1.Pod, opts metav1.CreateOptions) (*corev1.Pod, error)
	GetPod(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Pod, error)
	GetRaw(ctx context.Context, path string) (string, error)
	DeletePod(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	GetStatefulSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.StatefulSet, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	GetCronJob(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*batchv1.CronJob, error)
	GetLogs(ctx context.Context, namespace, name, container string, opts corev1.PodLogOptions) (string, error)
	GetPodsTable(ctx context.Context) (*metav1.Table, error)
	ProxyGet(ctx context.Context, namespace, name, url string) (string, error)
	ProxyTCP(ctx context.Context, namespace, name string, port uint16, handler func(io.ReadWriteCloser) error) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	GetCiliumVersion(ctx context.Context, p *corev1.Pod) (*semver.Version, error)
	GetVersion(ctx context.Context) (string, error)
	GetHelmMetadata(ctx context.Context, releaseName string, namespace string) (string, error)
	GetHelmValues(ctx context.Context, releaseName string, namespace string) (string, error)
	ListCiliumBGPPeeringPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumBGPPeeringPolicyList, error)
	ListCiliumCIDRGroups(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumCIDRGroupList, error)
	ListCiliumClusterwideNetworkPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error)
	ListCiliumClusterwideEnvoyConfigs(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideEnvoyConfigList, error)
	ListCiliumIdentities(ctx context.Context) (*ciliumv2.CiliumIdentityList, error)
	ListCiliumEgressGatewayPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumEgressGatewayPolicyList, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	ListCiliumEndpointSlices(ctx context.Context, options metav1.ListOptions) (*ciliumv2alpha1.CiliumEndpointSliceList, error)
	ListCiliumEnvoyConfigs(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEnvoyConfigList, error)
	ListCiliumExternalWorkloads(ctx context.Context, options metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error)
	ListCiliumLoadBalancerIPPools(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumLoadBalancerIPPoolList, error)
	ListCiliumLocalRedirectPolicies(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumLocalRedirectPolicyList, error)
	ListCiliumNetworkPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumNetworkPolicyList, error)
	ListCiliumNodes(ctx context.Context) (*ciliumv2.CiliumNodeList, error)
	ListCiliumNodeConfigs(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumNodeConfigList, error)
	ListCiliumPodIPPools(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumPodIPPoolList, error)
	ListDaemonSet(ctx context.Context, namespace string, o metav1.ListOptions) (*appsv1.DaemonSetList, error)
	ListEvents(ctx context.Context, o metav1.ListOptions) (*corev1.EventList, error)
	ListEndpoints(ctx context.Context, o metav1.ListOptions) (*corev1.EndpointsList, error)
	ListIngressClasses(ctx context.Context, o metav1.ListOptions) (*networkingv1.IngressClassList, error)
	ListIngresses(ctx context.Context, o metav1.ListOptions) (*networkingv1.IngressList, error)
	ListNamespaces(ctx context.Context, o metav1.ListOptions) (*corev1.NamespaceList, error)
	ListNetworkPolicies(ctx context.Context, o metav1.ListOptions) (*networkingv1.NetworkPolicyList, error)
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	ListServices(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.ServiceList, error)
	ListUnstructured(ctx context.Context, gvr schema.GroupVersionResource, namespace *string, o metav1.ListOptions) (*unstructured.UnstructuredList, error)
}
