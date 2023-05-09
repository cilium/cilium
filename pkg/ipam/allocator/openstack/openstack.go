// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package openstack

import (
	"context"
	"fmt"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/openstack/api"
	"github.com/cilium/cilium/pkg/openstack/eni"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-openstack")

// AllocatorOpenStack is an implementation of IPAM allocator interface for OpenStack ENI
type AllocatorOpenStack struct {
	client *api.Client
}

// Init sets up ENI limits based on given options
func (a *AllocatorOpenStack) Init(ctx context.Context) error {
	var aMetrics api.MetricsAPI

	if operatorOption.Config.EnableMetrics {
		aMetrics = apiMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, "openstack`", operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
	}

	var err error
	networkID := operatorOption.Config.OpenStackNetworkID
	if networkID == "" {
		return err
	}

	subnetID := operatorOption.Config.OpenStackSubnetID
	projectID := operatorOption.Config.OpenStackProjectID

	a.client, err = api.NewClient(aMetrics, operatorOption.Config.IPAMAPIQPSLimit, operatorOption.Config.IPAMAPIBurst,
		map[string]string{api.NetworkID: networkID, api.SubnetID: subnetID, api.ProjectID: projectID})

	if err != nil {
		log.Errorf("Failed to init openstack client with error: %s", err)
		return err
	}

	return nil
}

// Start kicks off ENI allocation, the initial connection to OpenStack
// APIs is done in a blocking manner. Provided this is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (a *AllocatorOpenStack) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	var iMetrics ipam.MetricsAPI

	log.Info("Starting OpenStack ENI allocator...")

	if operatorOption.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, operatorMetrics.Registry)
	} else {
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}
	instances := eni.NewInstancesManager(a.client)
	nodeManager, err := ipam.NewNodeManager(instances, getterUpdater, iMetrics,
		operatorOption.Config.ParallelAllocWorkers, operatorOption.Config.OpenStackReleaseExcessIPs, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize openstack node manager: %w", err)
	}

	if err := nodeManager.Start(ctx); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
