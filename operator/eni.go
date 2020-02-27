// Copyright 2019-2020 Authors of Cilium
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

	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	ec2shim "github.com/cilium/cilium/pkg/aws/ec2"
	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/controller"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/option"

	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var nodeManager *eni.NodeManager

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

// startENIAllocator kicks of ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func startENIAllocator(awsClientQPSLimit float64, awsClientBurst int, eniTags map[string]string) error {
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

	var (
		ec2Client *ec2shim.Client
		instances *eni.InstancesManager
	)

	if option.Config.EnableMetrics {
		aMetrics := apiMetrics.NewPrometheusMetrics("ipam", metricNamespace, registry)
		ec2Client = ec2shim.NewClient(ec2.New(cfg), aMetrics, awsClientQPSLimit, awsClientBurst)
		log.Info("Connected to EC2 service API")
		iMetrics := ipamMetrics.NewPrometheusMetrics(metricNamespace, registry)
		instances = eni.NewInstancesManager(ec2Client, iMetrics)
		nodeManager, err = eni.NewNodeManager(instances, ec2Client, &k8sAPI{}, iMetrics, option.Config.ParallelAllocWorkers, eniTags)
		if err != nil {
			return fmt.Errorf("unable to initialize ENI node manager: %s", err)
		}
	} else {
		ec2Client = ec2shim.NewClient(ec2.New(cfg), &apiMetrics.NoOpMetrics{}, awsClientQPSLimit, awsClientBurst)
		log.Info("Connected to EC2 service API")
		instances = eni.NewInstancesManager(ec2Client, &ipamMetrics.NoOpMetrics{})
		nodeManager, err = eni.NewNodeManager(instances, ec2Client, &k8sAPI{}, &ipamMetrics.NoOpMetrics{}, option.Config.ParallelAllocWorkers, eniTags)
		if err != nil {
			return fmt.Errorf("unable to initialize ENI node manager: %s", err)
		}
	}

	// Initial blocking synchronization of all ENIs and subnets
	instances.Resync(context.TODO())

	// Start an interval based  background resync for safety, it will
	// synchronize the state regularly and resolve eventual deficit if the
	// event driven trigger fails, and also release excess IP addresses
	// if release-excess-ips is enabled
	go func() {
		time.Sleep(time.Minute)
		mngr := controller.NewManager()
		mngr.UpdateController("eni-refresh",
			controller.ControllerParams{
				RunInterval: time.Minute,
				DoFunc: func(ctx context.Context) error {
					syncTime := instances.Resync(ctx)
					nodeManager.Resync(ctx, syncTime)
					return nil
				},
			})
	}()

	return nil
}
