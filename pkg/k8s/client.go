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

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	goerrors "errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/nodeaddress"

	log "github.com/sirupsen/logrus"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// ErrNilNode is returned when the Kubernetes API server has returned a nil node
	ErrNilNode = goerrors.New("API server returned nil node")

	// crdGV is the GroupVersion used for CRDs
	crdGV = schema.GroupVersion{
		Group:   CustomResourceDefinitionGroup,
		Version: CustomResourceDefinitionVersion,
	}
)

const (
	// CustomResourceDefinitionSingularName is the singular name of custom resource definition
	CustomResourceDefinitionSingularName = "ciliumnetworkpolicy"

	// ThirdPartyResourcesSingularName is the singular name of third party resources
	ThirdPartyResourcesSingularName = "cilium-network-policy"

	// CustomResourceDefinitionPluralName is the plural name of custom resource definition
	CustomResourceDefinitionPluralName = "ciliumnetworkpolicies"

	// CustomResourceDefinitionKind is the Kind name of custom resource definition
	CustomResourceDefinitionKind = "CiliumNetworkPolicy"

	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = "cilium.io"

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v2"

	// ThirdPartyResourceVersion is the version of the TPR resource
	ThirdPartyResourceVersion = "v1"
)

// CreateConfig creates a rest.Config for a given endpoint using a kubeconfig file.
func createConfig(endpoint, kubeCfgPath string) (*rest.Config, error) {
	// If the endpoint and the kubeCfgPath are empty then we can try getting
	// the rest.Config from the InClusterConfig
	if endpoint == "" && kubeCfgPath == "" {
		return rest.InClusterConfig()
	}

	if kubeCfgPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeCfgPath)
	}

	config := &rest.Config{Host: endpoint}
	err := rest.SetKubernetesDefaults(config)

	return config, err
}

// CreateConfigFromAgentResponse creates a client configuration from a
// models.DaemonConfigurationResponse
func CreateConfigFromAgentResponse(resp *models.DaemonConfigurationResponse) (*rest.Config, error) {
	return createConfig(resp.K8sEndpoint, resp.K8sConfiguration)
}

// CreateConfig creates a client configuration based on the configured API
// server and Kubeconfig path
func CreateConfig() (*rest.Config, error) {
	return createConfig(GetAPIServer(), GetKubeconfigPath())
}

// CreateClient creates a new client to access the Kubernetes API
func CreateClient(config *rest.Config) (*kubernetes.Clientset, error) {
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	wait.Until(func() {
		log.Infof("Waiting for kubernetes api-server to be ready...")
		err := isConnReady(cs)
		if err == nil {
			close(stop)
			return
		}
		select {
		case <-timeout.C:
			log.Errorf("Unable to contact kubernetes api-server %s: %s", config.Host, err)
			close(stop)
		default:
		}
	}, 5*time.Second, stop)
	log.Infof("Connected to kubernetes api-server %s", config.Host)
	return cs, nil
}

// isConnReady returns the err for the controller-manager status
func isConnReady(c *kubernetes.Clientset) error {
	_, err := c.CoreV1().ComponentStatuses().Get("controller-manager", metav1.GetOptions{})
	return err
}

// CreateThirdPartyResourcesDefinitions creates the TPR object in the kubernetes
// cluster
func CreateThirdPartyResourcesDefinitions(cli kubernetes.Interface) error {
	cnpTPRName := ThirdPartyResourcesSingularName + "." + CustomResourceDefinitionGroup
	res := &v1beta1.ThirdPartyResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: cnpTPRName,
		},
		Description: "Cilium network policy rule",
		Versions: []v1beta1.APIVersion{
			{Name: ThirdPartyResourceVersion},
		},
	}

	_, err := cli.ExtensionsV1beta1().ThirdPartyResources().Create(res)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	log.Infof("k8s: Waiting for TPR to be established in k8s api-server...")
	// wait for TPR being established
	err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		_, err := cli.ExtensionsV1beta1().ThirdPartyResources().Get(cnpTPRName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		// The only way we can know if the TPR was installed in the cluster
		// is to check if the return error was or not nil
		return true, nil
	})
	if err != nil {
		deleteErr := cli.ExtensionsV1beta1().ThirdPartyResources().Delete(cnpTPRName, nil)
		if deleteErr != nil {
			return fmt.Errorf("k8s: unable to delete TPR %s. Deleting TPR due: %s", deleteErr, err)
		}
		return err
	}

	return nil
}

// CreateCustomResourceDefinitions creates the CRD object in the kubernetes
// cluster
func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {
	cnpCRDName := CustomResourceDefinitionPluralName + "." + crdGV.Group

	res := &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: cnpCRDName,
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   crdGV.Group,
			Version: crdGV.Version,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     CustomResourceDefinitionPluralName,
				Singular:   CustomResourceDefinitionSingularName,
				ShortNames: []string{"cnp", "ciliumnp"},
				Kind:       CustomResourceDefinitionKind,
			},
			Scope: apiextensionsv1beta1.NamespaceScoped,
		},
	}

	_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(res)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	log.Infof("k8s: Waiting for CRD to be established in k8s api-server...")
	// wait for CRD being established
	err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		crd, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(cnpCRDName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1beta1.Established:
				if cond.Status == apiextensionsv1beta1.ConditionTrue {
					return true, err
				}
			case apiextensionsv1beta1.NamesAccepted:
				if cond.Status == apiextensionsv1beta1.ConditionFalse {
					log.Errorf("Name conflict: %v", cond.Reason)
					return false, err
				}
			}
		}
		return false, err
	})
	if err != nil {
		deleteErr := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(cnpCRDName, nil)
		if deleteErr != nil {
			return fmt.Errorf("k8s: unable to delete CRD %s. Deleting CRD due: %s", deleteErr, err)
		}
		return err
	}

	return nil
}

func addKnownTypesCRD(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		crdGV,
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, crdGV)

	return nil
}

type cnpClient struct {
	*rest.RESTClient
}

// CNPCliInterface is the interface for the CNP client
type CNPCliInterface interface {
	Update(cnp *CiliumNetworkPolicy) (*CiliumNetworkPolicy, error)
	Create(cnp *CiliumNetworkPolicy) (*CiliumNetworkPolicy, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string) (*CiliumNetworkPolicy, error)
	List(namespace string) (*CiliumNetworkPolicyList, error)
	ListAll() (*CiliumNetworkPolicyList, error)
	NewListWatch() *cache.ListWatch
}

// CreateCRDClient creates a new k8s client for custom resource definition
func CreateCRDClient(cfg *rest.Config) (CNPCliInterface, error) {
	schemeBuilder := runtime.NewSchemeBuilder(addKnownTypesCRD)
	sch := runtime.NewScheme()
	if err := schemeBuilder.AddToScheme(sch); err != nil {
		return nil, err
	}

	config := *cfg
	config.GroupVersion = &crdGV
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: serializer.NewCodecFactory(sch)}

	rc, err := rest.RESTClientFor(&config)
	return &cnpClient{rc}, err
}

// Update updates the given CNP and returns the object returned from the
// api-server and respective error.
func (c *cnpClient) Update(cnp *CiliumNetworkPolicy) (*CiliumNetworkPolicy, error) {
	var res CiliumNetworkPolicy
	ns := ExtractNamespace(&cnp.Metadata)
	err := c.RESTClient.Put().Resource(CustomResourceDefinitionPluralName).
		Namespace(ns).Name(cnp.Metadata.Name).
		Body(cnp).Do().Into(&res)
	return &res, err
}

// Create creates the given CNP and returns the object returned from the
// api-server and respective error.
func (c *cnpClient) Create(cnp *CiliumNetworkPolicy) (*CiliumNetworkPolicy, error) {
	var res CiliumNetworkPolicy
	ns := ExtractNamespace(&cnp.Metadata)
	err := c.RESTClient.Post().Resource(CustomResourceDefinitionPluralName).
		Namespace(ns).
		Body(cnp).Do().Into(&res)
	return &res, err
}

// Create deletes the CNP with the name in the namespace.
func (c *cnpClient) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	return c.RESTClient.Delete().
		Namespace(namespace).Resource(CustomResourceDefinitionPluralName).
		Name(name).Body(options).Do().
		Error()
}

// Get gets CNP CRD from the kube-apiserver
func (c *cnpClient) Get(namespace, name string) (*CiliumNetworkPolicy, error) {
	var result CiliumNetworkPolicy
	err := c.RESTClient.Get().
		Namespace(namespace).Resource(CustomResourceDefinitionPluralName).
		Name(name).Do().Into(&result)
	return &result, err
}

// List returns the list of CNPs in the given namespace
func (c *cnpClient) List(namespace string) (*CiliumNetworkPolicyList, error) {
	var result CiliumNetworkPolicyList
	err := c.RESTClient.Get().
		Namespace(namespace).Resource(CustomResourceDefinitionPluralName).
		Do().Into(&result)
	return &result, err
}

// ListAll returns the list of CNPs in all the namespaces
func (c *cnpClient) ListAll() (*CiliumNetworkPolicyList, error) {
	var result CiliumNetworkPolicyList
	err := c.RESTClient.Get().
		Resource(CustomResourceDefinitionPluralName).
		Do().Into(&result)
	return &result, err
}

// NewListWatch returns a ListWatch for cilium CRD on all namespaces.
func (c *cnpClient) NewListWatch() *cache.ListWatch {
	return cache.NewListWatchFromClient(c.RESTClient,
		CustomResourceDefinitionPluralName,
		v1.NamespaceAll,
		fields.Everything())
}

func addKnownTypesTPR(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		schema.GroupVersion{
			Group:   CustomResourceDefinitionGroup,
			Version: ThirdPartyResourceVersion,
		},
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
		&metav1.ListOptions{},
		&metav1.DeleteOptions{},
	)

	return nil
}

// CreateTPRClient creates a new k8s client for third party resources
func CreateTPRClient(config *rest.Config) (CNPCliInterface, error) {
	config.GroupVersion = &schema.GroupVersion{
		Group:   CustomResourceDefinitionGroup,
		Version: ThirdPartyResourceVersion,
	}
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: api.Codecs}
	schemeBuilder := runtime.NewSchemeBuilder(addKnownTypesTPR)
	schemeBuilder.AddToScheme(api.Scheme)

	rc, err := rest.RESTClientFor(config)
	return &cnpClient{rc}, err
}

func updateNodeAnnotation(c kubernetes.Interface, node *v1.Node, v4CIDR, v6CIDR *net.IPNet) (*v1.Node, error) {
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}

	if v4CIDR != nil {
		node.Annotations[Annotationv4CIDRName] = v4CIDR.String()
	}

	if v6CIDR != nil {
		node.Annotations[Annotationv6CIDRName] = v6CIDR.String()
	}

	node, err := c.CoreV1().Nodes().Update(node)
	if err != nil {
		return nil, err
	}

	if node == nil {
		return nil, ErrNilNode
	}

	return node, nil
}

// AnnotateNodeCIDR writes both v4 and v6 CIDRs in the given k8s node name.
// In case of failure while updating the node, this function while spawn a go
// routine to retry the node update indefinitely.
func AnnotateNodeCIDR(c kubernetes.Interface, nodeName string, v4CIDR, v6CIDR *net.IPNet) error {
	log.WithFields(log.Fields{
		fieldNodeName: nodeName,
		fieldSubsys:   subsysKubernetes,
	}).Debugf("Updating node annotations with node CIDRs: IPv4=%s IPv6=%s", v4CIDR, v6CIDR)

	go func(c kubernetes.Interface, nodeName string, v4CIDR, v6CIDR *net.IPNet) {
		var node *v1.Node
		var err error

		for n := 1; n <= maxUpdateRetries; n++ {
			node, err = GetNode(c, nodeName)
			if err == nil {
				node, err = updateNodeAnnotation(c, node, v4CIDR, v6CIDR)
			} else {
				if errors.IsNotFound(err) {
					err = ErrNilNode
				}
			}

			if err != nil {
				log.WithFields(log.Fields{
					fieldRetry:    n,
					fieldMaxRetry: maxUpdateRetries,
					fieldNodeName: nodeName,
					fieldSubsys:   subsysKubernetes,
				}).WithError(err).Error("Unable to update node resource with CIDR annotation")
			} else {
				break
			}

			time.Sleep(time.Duration(n) * time.Second)
		}
	}(c, nodeName, v4CIDR, v6CIDR)

	return nil
}

// UpdateCNPStatus updates the status into the given CNP. This function retries
// to do successful update into the kube-apiserver until it reaches the given
// timeout.
func UpdateCNPStatus(cnpClient CNPCliInterface, timeout time.Duration,
	ciliumRulesStore cache.Store, rule *CiliumNetworkPolicy, cnpns CiliumNetworkPolicyNodeStatus) {

	rule.SetPolicyStatus(nodeaddress.GetName(), cnpns)
	_, err := cnpClient.Update(rule)
	if err != nil {
		ns := ExtractNamespace(&rule.Metadata)
		name := rule.Metadata.GetObjectMeta().GetName()
		log.Warningf("k8s: unable to update CNP %s/%s with status: %s, retrying...", ns, name, err)
		t := time.NewTimer(timeout)
		defer t.Stop()
		loopTimer := time.NewTimer(time.Second)
		defer loopTimer.Stop()
		for n := 0; ; n++ {
			serverRuleStore, exists, err := ciliumRulesStore.Get(rule)
			if !exists {
				break
			}
			if err != nil {
				log.Warningf("k8s: unable to get k8s CNP %s/%s from local cache: %s", ns, name, err)
				break
			}
			serverRule, ok := serverRuleStore.(*CiliumNetworkPolicy)
			if !ok {
				log.Warningf("Received unknown object %+v, expected a CiliumNetworkPolicy object", serverRuleStore)
				return
			}
			if serverRule.Metadata.UID != rule.Metadata.UID &&
				serverRule.SpecEquals(rule) {
				// Although the policy was found this means it was deleted,
				// and re-added with the same name.
				log.Debugf("k8s: rule %s/%s changed while updating node status, stopping retry", ns, name)
				break
			}
			serverRule.SetPolicyStatus(nodeaddress.GetName(), cnpns)
			_, err = cnpClient.Update(serverRule)
			if err == nil {
				log.Debugf("k8s: successfully updated %s/%s with status: %s", ns, name, serverRule.Status)
				break
			}
			loopTimer.Reset(time.Duration(n) * time.Second)
			select {
			case <-t.C:
				log.Errorf("k8s: unable to update CNP %s/%s with status: %s", ns, name, err)
				break
			case <-loopTimer.C:
			}
			log.Warningf("k8s: unable to update CNP %s/%s with status: %s, retrying...", ns, name, err)
		}
	}
}

var (
	client kubernetes.Interface
)

// Client returns the default Kubernetes client
func Client() kubernetes.Interface {
	return client
}

func createDefaultClient() error {
	restConfig, err := CreateConfig()
	if err != nil {
		return fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}

	k8sClient, err := CreateClient(restConfig)
	if err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	client = k8sClient

	return nil
}
