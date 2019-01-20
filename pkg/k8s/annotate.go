// Copyright 2016-2018 Authors of Cilium
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
	"net"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// K8sClient is a wrapper around kubernetes.Interface.
type K8sClient struct {
	// kubernetes.Interface is the object through which interactions with
	// Kubernetes are performed.
	kubernetes.Interface
}

// AnnotatePod adds a Kubernetes annotation with key annotationKey and value
// annotationValue
func (k8sCli K8sClient) AnnotatePod(k8sNamespace, k8sPodName, annotationKey, annotationValue string) error {

	pod, err := k8sCli.CoreV1().Pods(k8sNamespace).Get(k8sPodName, meta_v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to annotate pod, cannot retrieve pod: %s", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations[annotationKey] = annotationValue
	pod, err = k8sCli.CoreV1().Pods(k8sNamespace).Update(pod)
	if err != nil {
		return fmt.Errorf("unable to annotate pod, cannot update pod: %s", err)
	}
	return nil
}

func updateNodeAnnotation(c kubernetes.Interface, node *v1.Node, v4CIDR, v6CIDR *cidr.CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP net.IP) (*v1.Node, error) {
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

	if v4CiliumHostIP != nil {
		node.Annotations[annotation.CiliumHostIP] = v4CiliumHostIP.String()
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
func (k8sCli K8sClient) AnnotateNode(nodeName string, v4CIDR, v6CIDR *cidr.CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP net.IP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName:       nodeName,
		logfields.V4Prefix:       v4CIDR,
		logfields.V6Prefix:       v6CIDR,
		logfields.V4HealthIP:     v4HealthIP,
		logfields.V6HealthIP:     v6HealthIP,
		logfields.V4CiliumHostIP: v4CiliumHostIP,
	})
	scopedLog.Debug("Updating node annotations with node CIDRs")

	go func(c kubernetes.Interface, nodeName string, v4CIDR, v6CIDR *cidr.CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP net.IP) {
		var node *v1.Node
		var err error

		for n := 1; n <= maxUpdateRetries; n++ {
			node, err = GetNode(c, nodeName)
			switch {
			case err == nil:
				_, err = updateNodeAnnotation(c, node, v4CIDR, v6CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP)
			case errors.IsNotFound(err):
				err = ErrNilNode
			}

			switch {
			case err == nil:
				return
			case errors.IsConflict(err):
				scopedLog.WithFields(logrus.Fields{
					fieldRetry:    n,
					fieldMaxRetry: maxUpdateRetries,
				}).WithError(err).Debugf("Unable to update node resource with annotation")
			default:
				scopedLog.WithFields(logrus.Fields{
					fieldRetry:    n,
					fieldMaxRetry: maxUpdateRetries,
				}).WithError(err).Warn("Unable to update node resource with annotation")
			}

			time.Sleep(time.Duration(n) * time.Second)
		}
	}(k8sCli, nodeName, v4CIDR, v6CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP)

	return nil
}
