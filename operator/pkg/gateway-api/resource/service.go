// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type ServiceResource struct {
	ResourceType   *corev1.Service
	registryConfig helpers.ResourceConfig
}

func NewServiceResource(r helpers.ResourceConfig) *ServiceResource {
	return &ServiceResource{
		ResourceType:   &corev1.Service{},
		registryConfig: r,
	}
}

// ShouldIndex - Services should never be indexed.
func (s *ServiceResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (s *ServiceResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (s *ServiceResource) GetResource() client.Object {
	return s.ResourceType
}

// ShouldWatch - Services should always be watched.
func (s *ServiceResource) ShouldWatch() bool {
	return true
}

func (s *ServiceResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	handlers = append(handlers, watchhandlers.EnqueueRequestForBackendService(c, scheme, logger, controllerName))
	if s.registryConfig.IncludeInferencePools {
		handlers = append(handlers, watchhandlers.EnqueueRequestForOwningShadowService(c, logger, controllerName))
	}

	return handlers
}

func (s *ServiceResource) HandleStatus() bool {
	return false
}
