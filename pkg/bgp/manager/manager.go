// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package manager provides functionality relating to the integration between
// Cilium and MetalLB, namely providing abstractions that help manage MetalLB
// from Cilium.
package manager

import (
	"context"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/client"
)

// New creates a new BGP MetalLB manager. It contains the MetalLB service IP
// controller, which contains the allocator.
//
// New requires access to a cache.Store associated with the service watcher.
func New(ctx context.Context, clientset client.Clientset, indexer cache.Store) (*Manager, error) {
	ctrl, err := newMetalLBController(ctx, clientset)
	if err != nil {
		return nil, err
	}
	mgr := &Manager{
		controller: ctrl,

		queue: workqueue.New(),

		indexer: indexer,
	}
	go mgr.run()

	return mgr, nil
}

// Manager represents the BGP manager. It integrates Cilium with the MetalLB
// logic for allocating LB IPs for service objects of type LoadBalancer.
//
// This manager also subscribes and handles K8s services events from the
// watcher and pushes them into a queue. From the queue, they are processed by
// the reconciliation logic of MetalLB for LB IP allocation. To do this,
// Manager implements
// github.com/cilium/cilium/pkg/k8s/watchers/subscriber.Service and
// therefore is registered as a subscriber to the subscriber package to be
// called from the K8s watcher.
//
// Note that the LB IP allocation occurs only for services of type LoadBalancer
// in the service.Status.LoadBalancerStatus.Ingress field.
type Manager struct {
	controller Controller

	// queue holds all services that need to be reconciled.
	queue workqueue.Interface
	// indexer is the store containing all the slim_corev1.Service objects seen
	// by the watcher. This is used in order to handle delete events. See
	// comment inside (*Manager).run().
	indexer cache.Store
}

func (m *Manager) MarkSynced() {
	m.controller.MarkSynced()
}
