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
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = "cilium.io"

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v1"
)

// CreateConfig creates a rest.Config for a given endpoint using a kubeconfig file.
func CreateConfig(endpoint, kubeCfgPath string) (*rest.Config, error) {
	if kubeCfgPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeCfgPath)
	}

	config := &rest.Config{Host: endpoint}
	err := rest.SetKubernetesDefaults(config)

	return config, err
}

// CreateClient creates a new client to access the Kubernetes API
func CreateClient(config *rest.Config) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(config)
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		schema.GroupVersion{
			Group:   CustomResourceDefinitionGroup,
			Version: CustomResourceDefinitionVersion,
		},
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
		&metav1.ListOptions{},
		&metav1.DeleteOptions{},
	)

	return nil
}

// CreateCRDClient creates a new k8s client for third party resources
func CreateCRDClient(config *rest.Config) (*rest.RESTClient, error) {
	config.GroupVersion = &schema.GroupVersion{
		Group:   CustomResourceDefinitionGroup,
		Version: CustomResourceDefinitionVersion,
	}
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: api.Codecs}
	schemeBuilder := runtime.NewSchemeBuilder(addKnownTypes)
	schemeBuilder.AddToScheme(api.Scheme)

	return rest.RESTClientFor(config)
}

// AnnotateNodeCIDR writes both v4 and v6 CIDRs in the given k8s node name.
// In case of failure while updating the node, this function while spawn a go
// routine to retry the node update indefinitely.
func AnnotateNodeCIDR(c kubernetes.Interface, nodeName string, v4CIDR, v6CIDR *net.IPNet) error {
	k8sNode, err := c.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	// register IP CIDRs in node's annotations
	log.Debugf("k8s: Storing IPv4 CIDR %s in k8s node %s's annotations", v4CIDR, k8sNode.Name)
	log.Debugf("k8s: Storing IPv6 CIDR %s in k8s node %s's annotations", v6CIDR, k8sNode.Name)
	k8sNode.Annotations[Annotationv4CIDRName] = v4CIDR.String()
	k8sNode.Annotations[Annotationv6CIDRName] = v6CIDR.String()

	_, err = c.CoreV1().Nodes().Update(k8sNode)
	if err != nil {
		go func(c kubernetes.Interface, k8sServerNode *v1.Node, v4CIDR, v6CIDR *net.IPNet, err error) {
			// TODO: Retry forever?
			for n := 0; err != nil; {
				log.Errorf("k8s: unable to update node %s with IPv6 CIDR annotation: %s, retrying...", k8sServerNode.Name, err)
				// In case of an error let's retry until
				// we were able to set the annotations properly
				k8sServerNode.Annotations[Annotationv4CIDRName] = v4CIDR.String()
				k8sServerNode.Annotations[Annotationv6CIDRName] = v6CIDR.String()
				k8sServerNode, err = c.CoreV1().Nodes().Update(k8sNode)
				if n < 30 {
					n++
				}
				time.Sleep(time.Duration(n) * time.Second)
			}
		}(c, k8sNode, v4CIDR, v6CIDR, err)
	}
	return nil
}
