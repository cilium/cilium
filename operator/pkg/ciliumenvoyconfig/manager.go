// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	ciliumEnvoyLBPrefix = "cilium-envoy-lb"
)

type svcEvent string

type Manager struct {
	envoyConfigManager *envoyConfigManager

	queue              workqueue.RateLimitingInterface
	maxRetries         int
	idleTimeoutSeconds int

	client       client.Clientset
	serviceStore cache.Store
	ports        []string
	algorithm    string
}

// New returns a new Manager for CiliumEnvoyConfig
func New(ctx context.Context, client client.Clientset, indexer cache.Store, ports []string, algorithm string, idleTimeoutSeconds int) (*Manager, error) {
	manager := &Manager{
		queue:              workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		client:             client,
		serviceStore:       indexer,
		maxRetries:         10,
		idleTimeoutSeconds: idleTimeoutSeconds,
		ports:              ports,
		algorithm:          algorithm,
	}

	envoyConfigManager, err := newEnvoyConfigManager(ctx, client, manager.maxRetries, manager.idleTimeoutSeconds)
	if err != nil {
		return nil, err
	}
	manager.envoyConfigManager = envoyConfigManager

	return manager, nil
}

func (m *Manager) OnAddService(service *slim_corev1.Service) error {
	var (
		svcName   = service.Name
		scopedLog = log.WithField(logfields.ServiceName, svcName)
	)
	key, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		return err
	}

	if !IsLBProtocolAnnotationEnabled(service) && !hasAnyPort(service, m.ports) {
		return nil
	}

	scopedLog.Debug("adding event to queue")
	m.queue.Add(svcEvent(key))
	return nil
}

func hasAnyPort(svc *slim_corev1.Service, ports []string) bool {
	for _, p := range ports {
		for _, port := range svc.Spec.Ports {
			if p == getServiceFrontendPort(port) {
				return true
			}
		}
	}
	return false
}

func getServiceFrontendPort(port slim_corev1.ServicePort) string {
	if port.Port != 0 {
		return strconv.Itoa(int(port.Port))
	}
	if port.NodePort != 0 {
		return strconv.Itoa(int(port.NodePort))
	}
	return port.Name
}

func (m *Manager) OnUpdateService(_, newObj *slim_corev1.Service) error {
	var (
		svcName   = newObj.Name
		scopedLog = log.WithField(logfields.ServiceName, svcName)
	)
	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err != nil {
		return err
	}

	scopedLog.Debug("adding event to queue")
	m.queue.Add(svcEvent(key))
	return nil
}

func (m *Manager) OnDeleteService(_ *slim_corev1.Service) error {
	// Doing nothing here as clean up should be done via k8s OwnerReferences
	return nil
}

func (m *Manager) MarkSynced() {
	m.envoyConfigManager.MarkSynced()
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

func (m *Manager) processEvent(ctx context.Context, event interface{}) error {
	switch k := event.(type) {
	case svcEvent:
		n := string(k) // service namespace/name

		objFromCache, exists, err := m.serviceStore.GetByKey(n)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("service %s does not exist", n)
		}

		service, ok := objFromCache.(*slim_corev1.Service)
		if !ok {
			return fmt.Errorf("got invalid object from cache: %T", objFromCache)
		}
		if IsLBProtocolAnnotationEnabled(service) || hasAnyPort(service, m.ports) {
			return m.createEnvoyConfig(ctx, service)
		}
		return m.deleteEnvoyConfig(ctx, service)
	default:
		log.Debugf("Encountered an unknown key type %T in CEC controller", k)
		return fmt.Errorf("unknown key type %T", k)
	}
}

func (m *Manager) createEnvoyConfig(ctx context.Context, svc *slim_corev1.Service) error {
	desired, err := m.getEnvoyConfigForService(svc)
	if err != nil {
		return err
	}

	// check if the CiliumEnvoyConfig resource already exists
	key, err := cache.MetaNamespaceKeyFunc(desired)
	if err != nil {
		log.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}
	existingEnvoyConfig, exists, err := m.envoyConfigManager.getByKey(key)
	if err != nil {
		log.WithError(err).Warn("CiliumEnvoyConfig lookup failed")
		return err
	}

	scopedLog := log.WithField(logfields.ServiceKey, getName(svc))
	if exists {
		if desired.DeepEqual(existingEnvoyConfig) {
			log.WithField(logfields.CiliumEnvoyConfigName, key).Debug("No change for existing CiliumEnvoyConfig")
			return nil
		}
		// Update existing CEC
		newEnvoyConfig := existingEnvoyConfig.DeepCopy()
		newEnvoyConfig.Spec = desired.Spec

		c, err := json.Marshal(existingEnvoyConfig)
		if err != nil {
			return err
		}
		d, err := json.Marshal(newEnvoyConfig)
		if err != nil {
			return nil
		}
		patch, err := strategicpatch.CreateTwoWayMergePatch(c, d, ciliumv2.CiliumEnvoyConfig{})
		if err != nil {
			return err
		}
		_, err = m.client.CiliumV2().CiliumEnvoyConfigs(svc.Namespace).Patch(ctx, newEnvoyConfig.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{
			FieldManager: Subsys,
		})
		if err != nil {
			scopedLog.WithError(err).Error("Failed to update CiliumEnvoyConfig for service")
			return err
		}
		scopedLog.Debug("Updated CiliumEnvoyConfig for service")
		return nil
	}

	_, err = m.client.CiliumV2().CiliumEnvoyConfigs(svc.Namespace).Create(ctx, desired, metav1.CreateOptions{
		FieldManager: Subsys,
	})
	if err != nil {
		scopedLog.WithError(err).Error("Failed to create CiliumEnvoyConfig for service")
		return err
	}
	scopedLog.Debug("Created CiliumEnvoyConfig for service")
	return nil
}

func (m *Manager) deleteEnvoyConfig(ctx context.Context, svc *slim_corev1.Service) error {
	cecName := fmt.Sprintf("%s-%s", ciliumEnvoyLBPrefix, svc.GetName())
	// check if the CiliumEnvoyConfig resource already exists
	_, exist, err := m.envoyConfigManager.getByKey(fmt.Sprintf("%s/%s", svc.Namespace, cecName))
	if !exist || err != nil {
		return err
	}
	err = m.client.CiliumV2().CiliumEnvoyConfigs(svc.Namespace).Delete(ctx, cecName, metav1.DeleteOptions{})
	if err != nil {
		log.WithField(logfields.ServiceKey, getName(svc)).WithError(err).Error("Failed to delete CiliumEnvoyConfig for service")
		return err
	}
	return nil
}
