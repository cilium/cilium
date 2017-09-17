/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ipam

import (
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	informers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/cloudprovider"
)

type nodeAndCIDR struct {
	cidr     *net.IPNet
	nodeName string
}

// CIDRAllocatorType is the type of the allocator to use.
type CIDRAllocatorType string

const (
	// RangeAllocatorType is the allocator that uses an internal CIDR
	// range allocator to do node CIDR range allocations.
	RangeAllocatorType CIDRAllocatorType = "RangeAllocator"
	// CloudAllocatorType is the allocator that uses cloud platform
	// support to do node CIDR range allocations.
	CloudAllocatorType CIDRAllocatorType = "CloudAllocator"
	// IPAMFromClusterAllocatorType uses the ipam controller sync'ing the node
	// CIDR range allocations from the cluster to the cloud.
	IPAMFromClusterAllocatorType = "IPAMFromCluster"
	// IPAMFromCloudAllocatorType uses the ipam controller sync'ing the node
	// CIDR range allocations from the cloud to the cluster.
	IPAMFromCloudAllocatorType = "IPAMFromCloud"

	// The amount of time the nodecontroller polls on the list nodes endpoint.
	apiserverStartupGracePeriod = 10 * time.Minute
)

// CIDRAllocator is an interface implemented by things that know how
// to allocate/occupy/recycle CIDR for nodes.
type CIDRAllocator interface {
	// AllocateOrOccupyCIDR looks at the given node, assigns it a valid
	// CIDR if it doesn't currently have one or mark the CIDR as used if
	// the node already have one.
	AllocateOrOccupyCIDR(node *v1.Node) error
	// ReleaseCIDR releases the CIDR of the removed node
	ReleaseCIDR(node *v1.Node) error
	// Register allocator with the nodeInformer for updates.
	Register(nodeInformer informers.NodeInformer)
}

// New creates a new CIDR range allocator.
func New(kubeClient clientset.Interface, cloud cloudprovider.Interface, allocatorType CIDRAllocatorType, clusterCIDR, serviceCIDR *net.IPNet, nodeCIDRMaskSize int) (CIDRAllocator, error) {
	nodeList, err := listNodes(kubeClient)
	if err != nil {
		return nil, err
	}

	switch allocatorType {
	case RangeAllocatorType:
		return NewCIDRRangeAllocator(kubeClient, clusterCIDR, serviceCIDR, nodeCIDRMaskSize, nodeList)
	case CloudAllocatorType:
		return NewCloudCIDRAllocator(kubeClient, cloud)
	default:
		return nil, fmt.Errorf("Invalid CIDR allocator type: %v", allocatorType)
	}
}

func listNodes(kubeClient clientset.Interface) (*v1.NodeList, error) {
	var nodeList *v1.NodeList
	// We must poll because apiserver might not be up. This error causes
	// controller manager to restart.
	if pollErr := wait.Poll(10*time.Second, apiserverStartupGracePeriod, func() (bool, error) {
		var err error
		nodeList, err = kubeClient.Core().Nodes().List(metav1.ListOptions{
			FieldSelector: fields.Everything().String(),
			LabelSelector: labels.Everything().String(),
		})
		if err != nil {
			glog.Errorf("Failed to list all nodes: %v", err)
			return false, nil
		}
		return true, nil
	}); pollErr != nil {
		return nil, fmt.Errorf("Failed to list all nodes in %v, cannot proceed without updating CIDR map",
			apiserverStartupGracePeriod)
	}
	return nodeList, nil
}
