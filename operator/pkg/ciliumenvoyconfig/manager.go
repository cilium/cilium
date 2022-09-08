// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

const (
	ciliumEnvoyLBPrefix = "cilium-envoy-lb"
)

type Manager struct {
	envoyConfigManager *envoyConfigManager

	queue      workqueue.RateLimitingInterface
	maxRetries int

	client       client.Clientset
	serviceStore cache.Store
}

// New returns a new Manager for CiliumEnvoyConfig
func New(client client.Clientset, indexer cache.Store) (*Manager, error) {
	manager := &Manager{
		queue:        workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		client:       client,
		serviceStore: indexer,
		maxRetries:   10,
	}

	envoyConfigManager, err := newEnvoyConfigManager(client, manager.maxRetries)
	if err != nil {
		return nil, err
	}
	manager.envoyConfigManager = envoyConfigManager

	return manager, nil
}

func (m *Manager) OnAddService(service *slim_corev1.Service) error {

	return nil
}

func (m *Manager) OnUpdateService(oldObj, newObj *slim_corev1.Service) error {
	return nil
}

func (m *Manager) OnDeleteService(service *slim_corev1.Service) error {
	return nil
}

// Run kicks off the controlled loop
func (m *Manager) Run(ctx context.Context) {
	defer m.queue.ShutDown()
	for {
		ev, quit := m.queue.Get()
		if quit {
			return
		}
		err := m.processEvent(ctx, ev)
		if err != nil {
			if m.queue.NumRequeues(ev) < m.maxRetries {
				log.WithError(err).Warning("Error while processing event, retrying")
				m.queue.AddRateLimited(ev)
				continue
			} else {
				log.WithError(err).Warning("Error while processing event, no more retries")
				m.queue.Forget(ev)
			}
		}
		m.queue.Done(ev)
	}
}

func (m *Manager) processEvent(ctx context.Context, ev interface{}) error {
	return nil
}
