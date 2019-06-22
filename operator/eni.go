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
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"

	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/sirupsen/logrus"
)

var nodeManager *eni.NodeManager

type k8sAPI struct{}

func (k *k8sAPI) UpdateStatus(node, origNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	// If k8s supports status as a sub-resource, then we need to update the status separately
	k8sCapabilities := k8sversion.Capabilities()
	switch {
	case k8sCapabilities.UpdateStatus:
		if !reflect.DeepEqual(origNode.Status, node.Status) {
			_, err := ciliumK8sClient.CiliumV2().CiliumNodes().UpdateStatus(node)
			if err != nil {
				return nil, err
			}
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
			newNode, err := ciliumK8sClient.CiliumV2().CiliumNodes().Update(node)
			if err != nil {
				return newNode, err
			}
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
		nodeManager.Update(resource)
	}
}

func ciliumNodeDeleted(nodeName string) {
	if nodeManager != nil {
		nodeManager.Delete(nodeName)
	}
}

// startENIAllocator kicks of ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func startENIAllocator() error {
	log.Info("Starting ENI allocator...")

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return fmt.Errorf("unable to load AWS configuration: %s", err)
	}

	log.Info("Retrieving own metadata from EC2 metadata server...")
	metadataClient := ec2metadata.New(cfg)
	instance, err := metadataClient.GetInstanceIdentityDocument()
	if err != nil {
		return fmt.Errorf("unable to retrieve instance identity document: %s", err)
	}

	log.WithFields(logrus.Fields{
		"instance": instance.InstanceID,
		"region":   instance.Region,
	}).Info("Connected to EC2 metadata server")

	cfg.Region = instance.Region

	eniMetrics := metrics.NewPrometheusMetrics(metricNamespace, registry)

	// Rate limit the EC2 API calls to 4/s with a burst of 2 tokens
	ec2Client := ec2shim.NewClient(ec2.New(cfg), eniMetrics, 4.0, 2)
	log.Info("Connected to EC2 service API")
	instances := eni.NewInstancesManager(ec2Client, eniMetrics)
	nodeManager, err = eni.NewNodeManager(instances, ec2Client, &k8sAPI{}, eniMetrics)
	if err != nil {
		return fmt.Errorf("unable to initialize ENI node manager: %s", err)
	}

	// Initial blocking synchronization of all ENIs and subnets
	instances.Resync()

	// Start an interval based  background resync for safety, it will
	// synchronize the state regularly and resolve eventual deficit if the
	// event driven trigger fails
	go func() {
		time.Sleep(time.Minute)
		mngr := controller.NewManager()
		mngr.UpdateController("eni-refresh",
			controller.ControllerParams{
				RunInterval: time.Minute,
				DoFunc: func(_ context.Context) error {
					instances.Resync()
					nodeManager.Resync()
					return nil
				},
			})
	}()

	return nil
}
