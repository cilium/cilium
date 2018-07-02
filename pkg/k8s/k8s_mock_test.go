// Copyright 2016-2017 Authors of Cilium
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

package k8s

import (
	"fmt"

	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	discovery "k8s.io/client-go/discovery"
	admissionregistrationv1alpha1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1alpha1"
	admissionregistrationv1beta1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1beta1"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	appsv1beta1 "k8s.io/client-go/kubernetes/typed/apps/v1beta1"
	appsv1beta2 "k8s.io/client-go/kubernetes/typed/apps/v1beta2"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authenticationv1beta1 "k8s.io/client-go/kubernetes/typed/authentication/v1beta1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	authorizationv1beta1 "k8s.io/client-go/kubernetes/typed/authorization/v1beta1"
	autoscalingv1 "k8s.io/client-go/kubernetes/typed/autoscaling/v1"
	autoscalingv2beta1 "k8s.io/client-go/kubernetes/typed/autoscaling/v2beta1"
	batchv1 "k8s.io/client-go/kubernetes/typed/batch/v1"
	batchv1beta1 "k8s.io/client-go/kubernetes/typed/batch/v1beta1"
	batchv2alpha1 "k8s.io/client-go/kubernetes/typed/batch/v2alpha1"
	certificatesv1beta1 "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	eventsv1beta1 "k8s.io/client-go/kubernetes/typed/events/v1beta1"
	extensionsv1beta1 "k8s.io/client-go/kubernetes/typed/extensions/v1beta1"
	networkingv1 "k8s.io/client-go/kubernetes/typed/networking/v1"
	policyv1beta1 "k8s.io/client-go/kubernetes/typed/policy/v1beta1"
	rbacv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	rbacv1alpha1 "k8s.io/client-go/kubernetes/typed/rbac/v1alpha1"
	rbacv1beta1 "k8s.io/client-go/kubernetes/typed/rbac/v1beta1"
	schedulingv1alpha1 "k8s.io/client-go/kubernetes/typed/scheduling/v1alpha1"
	schedulingv1beta1 "k8s.io/client-go/kubernetes/typed/scheduling/v1beta1"
	settingsv1alpha1 "k8s.io/client-go/kubernetes/typed/settings/v1alpha1"
	storagev1 "k8s.io/client-go/kubernetes/typed/storage/v1"
	storagev1alpha1 "k8s.io/client-go/kubernetes/typed/storage/v1alpha1"
	storagev1beta1 "k8s.io/client-go/kubernetes/typed/storage/v1beta1"
	"k8s.io/client-go/rest"
)

type NodeInterfaceClient struct {
	OnCreate           func(*v1.Node) (*v1.Node, error)
	OnUpdate           func(*v1.Node) (*v1.Node, error)
	OnUpdateStatus     func(*v1.Node) (*v1.Node, error)
	OnDelete           func(name string, options *meta_v1.DeleteOptions) error
	OnDeleteCollection func(options *meta_v1.DeleteOptions, listOptions meta_v1.ListOptions) error
	OnGet              func(name string, options meta_v1.GetOptions) (*v1.Node, error)
	OnList             func(opts meta_v1.ListOptions) (*v1.NodeList, error)
	OnWatch            func(opts meta_v1.ListOptions) (watch.Interface, error)
	OnPatch            func(name string, pt k8sTypes.PatchType, data []byte, subresources ...string) (result *v1.Node, err error)
	OnPatchStatus      func(nodeName string, data []byte) (*v1.Node, error)
}

func (nc *NodeInterfaceClient) Create(n *v1.Node) (*v1.Node, error) {
	if nc.OnCreate != nil {
		return nc.OnCreate(n)
	}
	return nil, fmt.Errorf("Method Create should not have been called")
}

func (nc *NodeInterfaceClient) Update(n *v1.Node) (*v1.Node, error) {
	if nc.OnUpdate != nil {
		return nc.OnUpdate(n)
	}
	return nil, fmt.Errorf("Method Update should not have been called")
}

func (nc *NodeInterfaceClient) UpdateStatus(n *v1.Node) (*v1.Node, error) {
	if nc.OnUpdateStatus != nil {
		return nc.OnUpdateStatus(n)
	}
	return nil, fmt.Errorf("Method UpdateStatus should not have been called")
}

func (nc *NodeInterfaceClient) Delete(name string, options *meta_v1.DeleteOptions) error {
	if nc.OnDelete != nil {
		return nc.OnDelete(name, options)
	}
	return fmt.Errorf("Method Delete should not have been called")
}

func (nc *NodeInterfaceClient) DeleteCollection(options *meta_v1.DeleteOptions, listOptions meta_v1.ListOptions) error {
	if nc.OnDeleteCollection != nil {
		return nc.OnDeleteCollection(options, listOptions)
	}
	return fmt.Errorf("Method DeleteCollection should not have been called")
}

func (nc *NodeInterfaceClient) Get(name string, options meta_v1.GetOptions) (*v1.Node, error) {
	if nc.OnGet != nil {
		return nc.OnGet(name, options)
	}
	return nil, fmt.Errorf("Method Get should not have been called")
}

func (nc *NodeInterfaceClient) List(opts meta_v1.ListOptions) (*v1.NodeList, error) {
	if nc.OnList != nil {
		return nc.OnList(opts)
	}
	return nil, fmt.Errorf("Method List should not have been called")
}

func (nc *NodeInterfaceClient) Watch(opts meta_v1.ListOptions) (watch.Interface, error) {
	if nc.OnWatch != nil {
		return nc.OnWatch(opts)
	}
	return nil, fmt.Errorf("Method Watch should not have been called")
}

func (nc *NodeInterfaceClient) Patch(name string, pt k8sTypes.PatchType, data []byte, subresources ...string) (result *v1.Node, err error) {
	if nc.OnPatch != nil {
		return nc.OnPatch(name, pt, data, subresources...)
	}
	return nil, fmt.Errorf("Method Patch should not have been called")
}

func (nc *NodeInterfaceClient) PatchStatus(nodeName string, data []byte) (*v1.Node, error) {
	if nc.OnPatchStatus != nil {
		return nc.OnPatchStatus(nodeName, data)
	}
	return nil, fmt.Errorf("Method PatchStatus should not have been called")
}

//
// CoreV1Client is used to interact with features provided by the  group.
type CoreV1Client struct {
	OnNodes func() corev1.NodeInterface
}

func (c *CoreV1Client) RESTClient() rest.Interface {
	return nil
}

func (c *CoreV1Client) ComponentStatuses() corev1.ComponentStatusInterface {
	return nil
}

func (c *CoreV1Client) ConfigMaps(namespace string) corev1.ConfigMapInterface {
	return nil
}

func (c *CoreV1Client) Endpoints(namespace string) corev1.EndpointsInterface {
	return nil
}

func (c *CoreV1Client) Events(namespace string) corev1.EventInterface {
	return nil
}

func (c *CoreV1Client) LimitRanges(namespace string) corev1.LimitRangeInterface {
	return nil
}

func (c *CoreV1Client) Namespaces() corev1.NamespaceInterface {
	return nil
}

func (c *CoreV1Client) Nodes() corev1.NodeInterface {
	if c.OnNodes != nil {
		return c.OnNodes()
	}
	panic("Method Nodes should not have been called")
}

func (c *CoreV1Client) PersistentVolumes() corev1.PersistentVolumeInterface {
	return nil
}

func (c *CoreV1Client) PersistentVolumeClaims(namespace string) corev1.PersistentVolumeClaimInterface {
	return nil
}

func (c *CoreV1Client) Pods(namespace string) corev1.PodInterface {
	return nil
}

func (c *CoreV1Client) PodTemplates(namespace string) corev1.PodTemplateInterface {
	return nil
}

func (c *CoreV1Client) ReplicationControllers(namespace string) corev1.ReplicationControllerInterface {
	return nil
}

func (c *CoreV1Client) ResourceQuotas(namespace string) corev1.ResourceQuotaInterface {
	return nil
}

func (c *CoreV1Client) Secrets(namespace string) corev1.SecretInterface {
	return nil
}

func (c *CoreV1Client) Services(namespace string) corev1.ServiceInterface {
	return nil
}

func (c *CoreV1Client) ServiceAccounts(namespace string) corev1.ServiceAccountInterface {
	return nil
}

type Clientset struct {
	OnCoreV1 func() corev1.CoreV1Interface
}

func (c Clientset) CoreV1() corev1.CoreV1Interface {
	if c.OnCoreV1 != nil {
		return c.OnCoreV1()
	}
	panic("Method CoreV1 should not have been called")
}

func (c Clientset) Core() corev1.CoreV1Interface {
	return nil
}

func (c Clientset) AdmissionregistrationV1alpha1() admissionregistrationv1alpha1.AdmissionregistrationV1alpha1Interface {
	return nil
}

func (c Clientset) AdmissionregistrationV1beta1() admissionregistrationv1beta1.AdmissionregistrationV1beta1Interface {
	return nil
}

func (c Clientset) Admissionregistration() admissionregistrationv1beta1.AdmissionregistrationV1beta1Interface {
	return nil
}

func (c Clientset) AppsV1beta1() appsv1beta1.AppsV1beta1Interface {
	return nil
}

func (c Clientset) AppsV1beta2() appsv1beta2.AppsV1beta2Interface {
	return nil
}

func (c Clientset) AppsV1() appsv1.AppsV1Interface {
	return nil
}

func (c Clientset) Apps() appsv1.AppsV1Interface {
	return nil
}

func (c Clientset) AuthenticationV1() authenticationv1.AuthenticationV1Interface {
	return nil
}

func (c Clientset) Authentication() authenticationv1.AuthenticationV1Interface {
	return nil
}

func (c Clientset) AuthenticationV1beta1() authenticationv1beta1.AuthenticationV1beta1Interface {
	return nil
}

func (c Clientset) AuthorizationV1() authorizationv1.AuthorizationV1Interface {
	return nil
}

func (c Clientset) Authorization() authorizationv1.AuthorizationV1Interface {
	return nil
}

func (c Clientset) AuthorizationV1beta1() authorizationv1beta1.AuthorizationV1beta1Interface {
	return nil
}

func (c Clientset) AutoscalingV1() autoscalingv1.AutoscalingV1Interface {
	return nil
}

func (c Clientset) Autoscaling() autoscalingv1.AutoscalingV1Interface {
	return nil
}

func (c Clientset) AutoscalingV2beta1() autoscalingv2beta1.AutoscalingV2beta1Interface {
	return nil
}

func (c Clientset) BatchV1() batchv1.BatchV1Interface {
	return nil
}

func (c Clientset) Batch() batchv1.BatchV1Interface {
	return nil
}

func (c Clientset) BatchV2alpha1() batchv2alpha1.BatchV2alpha1Interface {
	return nil
}

func (c Clientset) BatchV1beta1() batchv1beta1.BatchV1beta1Interface {
	return nil
}

func (c Clientset) CertificatesV1beta1() certificatesv1beta1.CertificatesV1beta1Interface {
	return nil
}

func (c Clientset) Certificates() certificatesv1beta1.CertificatesV1beta1Interface {
	return nil
}

func (c Clientset) EventsV1beta1() eventsv1beta1.EventsV1beta1Interface {
	return nil
}

func (c Clientset) Events() eventsv1beta1.EventsV1beta1Interface {
	return nil
}

func (c Clientset) ExtensionsV1beta1() extensionsv1beta1.ExtensionsV1beta1Interface {
	return nil
}

func (c Clientset) Extensions() extensionsv1beta1.ExtensionsV1beta1Interface {
	return nil
}

func (c Clientset) NetworkingV1() networkingv1.NetworkingV1Interface {
	return nil
}

func (c Clientset) Networking() networkingv1.NetworkingV1Interface {
	return nil
}

func (c Clientset) PolicyV1beta1() policyv1beta1.PolicyV1beta1Interface {
	return nil
}

func (c Clientset) Policy() policyv1beta1.PolicyV1beta1Interface {
	return nil
}

func (c Clientset) RbacV1beta1() rbacv1beta1.RbacV1beta1Interface {
	return nil
}

func (c Clientset) Rbac() rbacv1.RbacV1Interface {
	return nil
}

func (c Clientset) RbacV1alpha1() rbacv1alpha1.RbacV1alpha1Interface {
	return nil
}

func (c Clientset) RbacV1() rbacv1.RbacV1Interface {
	return nil
}

func (c Clientset) SettingsV1alpha1() settingsv1alpha1.SettingsV1alpha1Interface {
	return nil
}

func (c Clientset) Settings() settingsv1alpha1.SettingsV1alpha1Interface {
	return nil
}

func (c Clientset) SchedulingV1beta1() schedulingv1beta1.SchedulingV1beta1Interface {
	return nil
}

func (c Clientset) SchedulingV1alpha1() schedulingv1alpha1.SchedulingV1alpha1Interface {
	return nil
}

func (c Clientset) Scheduling() schedulingv1beta1.SchedulingV1beta1Interface {
	return nil
}

func (c Clientset) StorageV1alpha1() storagev1alpha1.StorageV1alpha1Interface {
	return nil
}

func (c Clientset) StorageV1beta1() storagev1beta1.StorageV1beta1Interface {
	return nil
}

func (c Clientset) StorageV1() storagev1.StorageV1Interface {
	return nil
}

func (c Clientset) Storage() storagev1.StorageV1Interface {
	return nil
}

func (c Clientset) Discovery() discovery.DiscoveryInterface {
	return nil
}
