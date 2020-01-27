// Copyright 2019 Authors of Cilium
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

package main

import (
	"context"
	"fmt"
	"reflect"
	"time"

	ec2shim "github.com/cilium/cilium/pkg/aws/ec2"
	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/aws/eni/metrics"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var nodeManager *ipam.NodeManager

type k8sAPI struct{}

func (k *k8sAPI) Get(node string) (*v2.CiliumNode, error) {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Get(node, metav1.GetOptions{})
}

func (k *k8sAPI) UpdateStatus(node, origNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	// If k8s supports status as a sub-resource, then we need to update the status separately
	k8sCapabilities := k8sversion.Capabilities()
	switch {
	case k8sCapabilities.UpdateStatus:
		if !reflect.DeepEqual(origNode.Status, node.Status) {
			return ciliumK8sClient.CiliumV2().CiliumNodes().UpdateStatus(node)
		}
	default:
		if !reflect.DeepEqual(origNode.Status, node.Status) {
			return ciliumK8sClient.CiliumV2().CiliumNodes().Update(node)
		}
	}

	return nil, nil
}

func (k *k8sAPI) Update(node, origNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	// If k8s supports status as a sub-resource, then we need to update the status separately
	k8sCapabilities := k8sversion.Capabilities()
	switch {
	case k8sCapabilities.UpdateStatus:
		if !reflect.DeepEqual(origNode.Spec, node.Spec) {
			return ciliumK8sClient.CiliumV2().CiliumNodes().Update(node)
		}
	default:
		if !reflect.DeepEqual(origNode, node) {
			return ciliumK8sClient.CiliumV2().CiliumNodes().Update(node)
		}
	}

	return nil, nil
}

func ciliumNodeUpdated(resource *v2.CiliumNode) {
	if nodeManager != nil {
		// resource is deep copied before it is stored in pkg/aws/eni
		nodeManager.Update(resource)
	}
}

func ciliumNodeDeleted(nodeName string) {
	if nodeManager != nil {
		nodeManager.Delete(nodeName)
	}
}
