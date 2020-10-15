// Copyright 2016-2020 Authors of Cilium
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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// K8sClient is a wrapper around kubernetes.Interface.
type K8sClient struct {
	// kubernetes.Interface is the object through which interactions with
	// Kubernetes are performed.
	kubernetes.Interface
}

// K8sCiliumClient is a wrapper around clientset.Interface.
type K8sCiliumClient struct {
	clientset.Interface
}

// K8sAPIExtensionsClient is a wrapper around clientset.Interface.
type K8sAPIExtensionsClient struct {
	apiextclientset.Interface
}

func updateNodeAnnotation(c kubernetes.Interface, nodeName string, encryptKey uint8, v4CIDR, v6CIDR *cidr.CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP, v6CiliumHostIP net.IP) error {
	annotations := map[string]string{}

	if v4CIDR != nil {
		annotations[annotation.V4CIDRName] = v4CIDR.String()
	}
	if v6CIDR != nil {
		annotations[annotation.V6CIDRName] = v6CIDR.String()
	}

	if v4HealthIP != nil {
		annotations[annotation.V4HealthName] = v4HealthIP.String()
	}
	if v6HealthIP != nil {
		annotations[annotation.V6HealthName] = v6HealthIP.String()
	}

	if v4CiliumHostIP != nil {
		annotations[annotation.CiliumHostIP] = v4CiliumHostIP.String()
	}

	if v6CiliumHostIP != nil {
		annotations[annotation.CiliumHostIPv6] = v6CiliumHostIP.String()
	}

	if encryptKey != 0 {
		annotations[annotation.CiliumEncryptionKey] = strconv.FormatUint(uint64(encryptKey), 10)
	}

	if len(annotations) == 0 {
		return nil
	}

	raw, err := json.Marshal(annotations)
	if err != nil {
		return err
	}
	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))

	_, err = c.CoreV1().Nodes().Patch(context.TODO(), nodeName, types.StrategicMergePatchType, patch, v1.PatchOptions{})

	return err
}

// AnnotateNode writes v4 and v6 CIDRs and health IPs in the given k8s node name.
// In case of failure while updating the node, this function while spawn a go
// routine to retry the node update indefinitely.
func (k8sCli K8sClient) AnnotateNode(nodeName string, encryptKey uint8, v4CIDR, v6CIDR *cidr.CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP, v6CiliumHostIP net.IP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName:       nodeName,
		logfields.V4Prefix:       v4CIDR,
		logfields.V6Prefix:       v6CIDR,
		logfields.V4HealthIP:     v4HealthIP,
		logfields.V6HealthIP:     v6HealthIP,
		logfields.V4CiliumHostIP: v4CiliumHostIP,
		logfields.V6CiliumHostIP: v6CiliumHostIP,
		logfields.Key:            encryptKey,
	})
	scopedLog.Debug("Updating node annotations with node CIDRs")

	controller.NewManager().UpdateController("update-k8s-node-annotations",
		controller.ControllerParams{
			DoFunc: func(_ context.Context) error {
				err := updateNodeAnnotation(k8sCli, nodeName, encryptKey, v4CIDR, v6CIDR, v4HealthIP, v6HealthIP, v4CiliumHostIP, v6CiliumHostIP)
				if err != nil {
					scopedLog.WithFields(logrus.Fields{}).WithError(err).Warn("Unable to patch node resource with annotation")
				}
				return err
			},
		})

	return nil
}

// GetSecrets returns the secrets found in the given namespace and name.
func (k8sCli K8sClient) GetSecrets(ctx context.Context, ns, name string) (map[string][]byte, error) {
	if k8sCli.Interface == nil {
		return nil, fmt.Errorf("GetSecrets: No k8s, cannot access k8s secrets")
	}

	result, err := k8sCli.CoreV1().Secrets(ns).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}
