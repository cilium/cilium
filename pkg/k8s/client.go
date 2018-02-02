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
	"github.com/cilium/cilium/pkg/annotation"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	cilium_v1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v1"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_client_v1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v1"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// ErrNilNode is returned when the Kubernetes API server has returned a nil node
	ErrNilNode = goerrors.New("API server returned nil node")
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
		log.Info("Waiting for k8s api-server to be ready...")
		err = isConnReady(cs)
		if err == nil {
			close(stop)
			return
		}
		select {
		case <-timeout.C:
			log.WithError(err).WithField(logfields.IPAddr, config.Host).Error("Unable to contact k8s api-server")
			close(stop)
		default:
		}
	}, 5*time.Second, stop)
	if err == nil {
		log.WithField(logfields.IPAddr, config.Host).Info("Connected to k8s api-server")
	}
	return cs, err
}

// isConnReady returns the err for the controller-manager status
func isConnReady(c *kubernetes.Clientset) error {
	_, err := c.CoreV1().ComponentStatuses().Get("controller-manager", metav1.GetOptions{})
	return err
}

func updateNodeAnnotation(c kubernetes.Interface, node *v1.Node, v4CIDR, v6CIDR *net.IPNet, v4HealthIP, v6HealthIP net.IP) (*v1.Node, error) {
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}

	if v4CIDR != nil {
		node.Annotations[annotation.V4CIDRName] = v4CIDR.String()
	}
	if v6CIDR != nil {
		node.Annotations[annotation.V6CIDRName] = v6CIDR.String()
	}

	if v4HealthIP != nil {
		node.Annotations[annotation.V4HealthName] = v4HealthIP.String()
	}
	if v6HealthIP != nil {
		node.Annotations[annotation.V6HealthName] = v6HealthIP.String()
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

// AnnotateNode writes v4 and v6 CIDRs and health IPs in the given k8s node name.
// In case of failure while updating the node, this function while spawn a go
// routine to retry the node update indefinitely.
func AnnotateNode(c kubernetes.Interface, nodeName string, v4CIDR, v6CIDR *net.IPNet, v4HealthIP, v6HealthIP net.IP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName:   nodeName,
		logfields.V4Prefix:   v4CIDR,
		logfields.V6Prefix:   v6CIDR,
		logfields.V4HealthIP: v4HealthIP,
		logfields.V6HealthIP: v6HealthIP,
	})
	scopedLog.Debug("Updating node annotations with node CIDRs")

	go func(c kubernetes.Interface, nodeName string, v4CIDR, v6CIDR *net.IPNet, v4HealthIP, v6HealthIP net.IP) {
		var node *v1.Node
		var err error

		for n := 1; n <= maxUpdateRetries; n++ {
			node, err = GetNode(c, nodeName)
			if err == nil {
				node, err = updateNodeAnnotation(c, node, v4CIDR, v6CIDR, v4HealthIP, v6HealthIP)
			} else {
				if errors.IsNotFound(err) {
					err = ErrNilNode
				}
			}

			if err != nil {
				scopedLog.WithFields(logrus.Fields{
					fieldRetry:    n,
					fieldMaxRetry: maxUpdateRetries,
				}).WithError(err).Error("Unable to update node resource with annotation")
			} else {
				break
			}

			time.Sleep(time.Duration(n) * time.Second)
		}
	}(c, nodeName, v4CIDR, v6CIDR, v4HealthIP, v6HealthIP)

	return nil
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

// UpdateCNPStatusV1 updates the status into the given CNP. This function retries
// to do successful update into the kube-apiserver until it reaches the given
// timeout.
func UpdateCNPStatusV1(ciliumNPClientV1 cilium_client_v1.CiliumV1Interface,
	ciliumRulesStore cache.Store, timeout time.Duration, nodeName string,
	rule *cilium_v1.CiliumNetworkPolicy, cnpns cilium_v1.CiliumNetworkPolicyNodeStatus) {

	rule.SetPolicyStatus(nodeName, cnpns)

	ns := k8sconst.ExtractNamespace(&rule.ObjectMeta)

	_, err := ciliumNPClientV1.CiliumNetworkPolicies(ns).Update(rule)
	if err == nil {
		// If the Update went successful no need to retry again
		return
	}

	name := rule.ObjectMeta.Name

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace:            ns,
		logfields.CiliumNetworkPolicyName: name,
	})
	scopedLog.WithError(err).Warn("unable to update CNP, retrying...")

	t := time.NewTimer(timeout)
	defer t.Stop()
	loopTimer := time.NewTimer(time.Second)
	defer loopTimer.Stop()
	for n := 1; ; n++ {
		serverRuleStore, exists, err := ciliumRulesStore.Get(rule)
		if !exists {
			return
		}
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to find v1.CiliumNetworkPolicy in local cache")
			return
		}
		serverRule, ok := serverRuleStore.(*cilium_v1.CiliumNetworkPolicy)
		if !ok {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				logfields.CiliumNetworkPolicy: logfields.Repr(serverRuleStore),
			}).Warn("Received object of unknown type from API server, expecting v1.CiliumNetworkPolicy")
			return
		}
		serverRuleCpy := serverRule.DeepCopy()
		_, err = serverRuleCpy.Parse()
		if err != nil {
			log.WithError(err).WithField(logfields.Object, logfields.Repr(serverRuleCpy)).
				Warn("Error parsing new CiliumNetworkPolicy rule")
			return
		}
		if serverRuleCpy.ObjectMeta.UID != rule.ObjectMeta.UID &&
			serverRuleCpy.SpecEquals(rule) {
			// Although the policy was found this means it was deleted,
			// and re-added with the same name.
			scopedLog.Debug("rule changed while updating node status, stopping retry")
			return
		}
		serverRuleCpy.SetPolicyStatus(nodeName, cnpns)
		_, err = ciliumNPClientV1.CiliumNetworkPolicies(ns).Update(serverRuleCpy)
		if err == nil {
			scopedLog.WithField("status", serverRuleCpy.Status).Debug("successfully updated with status")
			return
		}
		loopTimer.Reset(time.Duration(n) * time.Second)
		select {
		case <-t.C:
			scopedLog.WithError(err).Error("unable to update CNP with status due timeout")
			return
		case <-loopTimer.C:
		}
		scopedLog.WithError(err).Warn("unable to update CNP with status, retrying...")
	}
}

// UpdateCNPStatusV2 updates the status into the given CNP. This function retries
// to do successful update into the kube-apiserver until it reaches the given
// timeout.
func UpdateCNPStatusV2(ciliumNPClientV2 cilium_client_v2.CiliumV2Interface,
	ciliumRulesStore cache.Store, timeout time.Duration, nodeName string,
	rule *cilium_v2.CiliumNetworkPolicy, cnpns cilium_v2.CiliumNetworkPolicyNodeStatus) {

	rule.SetPolicyStatus(nodeName, cnpns)

	ns := k8sconst.ExtractNamespace(&rule.ObjectMeta)

	_, err := ciliumNPClientV2.CiliumNetworkPolicies(ns).Update(rule)
	if err == nil {
		// If the Update went successful no need to retry again
		return
	}

	name := rule.ObjectMeta.Name

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace:            ns,
		logfields.CiliumNetworkPolicyName: name,
	})
	scopedLog.WithError(err).Warn("unable to update CNP, retrying...")

	t := time.NewTimer(timeout)
	defer t.Stop()
	loopTimer := time.NewTimer(time.Second)
	defer loopTimer.Stop()
	for n := 1; ; n++ {
		serverRuleStore, exists, err := ciliumRulesStore.Get(rule)
		if !exists {
			return
		}
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to find v1.CiliumNetworkPolicy in local cache")
			return
		}
		serverRule, ok := serverRuleStore.(*cilium_v2.CiliumNetworkPolicy)
		if !ok {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				logfields.CiliumNetworkPolicy: logfields.Repr(serverRuleStore),
			}).Warn("Received object of unknown type from API server, expecting v1.CiliumNetworkPolicy")
			return
		}
		serverRuleCpy := serverRule.DeepCopy()
		_, err = serverRuleCpy.Parse()
		if err != nil {
			log.WithError(err).WithField(logfields.Object, logfields.Repr(serverRuleCpy)).
				Warn("Error parsing new CiliumNetworkPolicy rule")
			return
		}
		if serverRuleCpy.ObjectMeta.UID != rule.ObjectMeta.UID &&
			serverRuleCpy.SpecEquals(rule) {
			// Although the policy was found this means it was deleted,
			// and re-added with the same name.
			scopedLog.Debug("rule changed while updating node status, stopping retry")
			return
		}
		serverRuleCpy.SetPolicyStatus(nodeName, cnpns)
		_, err = ciliumNPClientV2.CiliumNetworkPolicies(ns).Update(serverRuleCpy)
		if err == nil {
			scopedLog.WithField("status", serverRuleCpy.Status).Debug("successfully updated with status")
			return
		}
		loopTimer.Reset(time.Duration(n) * time.Second)
		select {
		case <-t.C:
			scopedLog.WithError(err).Error("unable to update CNP with status due timeout")
			return
		case <-loopTimer.C:
		}
		scopedLog.WithError(err).Warn("unable to update CNP with status, retrying...")
	}
}
