// Copyright 2021 Authors of Cilium
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

// Package manager provides functionality relating to the integration between
// Cilium and MetalLB, namely providing abstractions that help manage MetalLB
// from Cilium.
package manager

import (
	"os"

	bgpconfig "github.com/cilium/cilium/pkg/bgp/config"
	bgpk8s "github.com/cilium/cilium/pkg/bgp/k8s"
	bgplog "github.com/cilium/cilium/pkg/bgp/log"
	"github.com/cilium/cilium/pkg/option"

	metallballoc "go.universe.tf/metallb/pkg/allocator"
	metallbctl "go.universe.tf/metallb/pkg/controller"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// New creates a new BGP MetalLB manager. It contains the MetalLB service IP
// controller, which contains the allocator.
//
// New requires access to a cache.Store associated with the service watcher.
func New(indexer cache.Store) *Manager {
	logger := &bgplog.Logger{Entry: log}
	c := &metallbctl.Controller{
		Client: bgpk8s.New(logger.Logger),
		IPs:    metallballoc.New(),
	}

	f, err := os.Open(option.Config.BGPConfigPath)
	if err != nil {
		log.WithError(err).Fatal("Failed to open BGP config file")
	}
	defer f.Close()

	config, err := bgpconfig.Parse(f)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse BGP configuration")
	}
	c.SetConfig(logger, config)

	mgr := &Manager{
		Controller: c,
		logger:     logger,

		queue:   workqueue.New(),
		indexer: indexer,
	}
	go mgr.run()

	return mgr
}

// Manager represents the BGP manager. It integrates Cilium with the MetalLB
// logic for allocating LB IPs for service objects of type LoadBalancer.
//
// This manager also subscribes and handles K8s services events from the
// watcher and pushes them into a queue. From the queue, they are processed by
// the reconciliation logic of MetalLB for LB IP allocation. To do this,
// Manager implements
// github.com/cilium/cilium/pkg/k8s/watchers/subscriber.ServiceHandler and
// therefore is registered as a subscriber to the subscriber package to be
// called from the K8s watcher.
//
// Note that the LB IP allocation occurs only for services of type LoadBalancer
// in the service.Status.LoadBalancerStatus.Ingress field.
type Manager struct {
	*metallbctl.Controller

	logger *bgplog.Logger

	// queue holds all services that need to be reconciled.
	queue workqueue.Interface
	// indexer is the store containing all the slim_corev1.Service objects seen
	// by the watcher. This is used in order to handle delete events. See
	// comment inside (*Manager).run().
	indexer cache.Store
}

// Logger returns the controller's logger.
func (c *Manager) Logger() *bgplog.Logger {
	return c.logger
}
