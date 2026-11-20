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

type ConfigMapResource struct {
	ResourceType   *corev1.ConfigMap
	registryConfig helpers.ResourceConfig
}

func NewConfigMapResource(r helpers.ResourceConfig) *ConfigMapResource {
	return &ConfigMapResource{
		ResourceType:   &corev1.ConfigMap{},
		registryConfig: r,
	}
}

// ShouldIndex - ConfigMaps should never be indexed.
func (cm *ConfigMapResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (cm *ConfigMapResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (cm *ConfigMapResource) GetResource() client.Object {
	return cm.ResourceType
}

// ShouldWatch - ConfigMaps should always be watched.
func (cm *ConfigMapResource) ShouldWatch() bool {
	return true
}

func (cm *ConfigMapResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	handlers = append(handlers, watchhandlers.EnqueueRequestForBackendTLSPolicyConfigMap(c, logger, controllerName))
	handlers = append(handlers, watchhandlers.EnqueueRequestForFrontendTLSConfigMap(c, logger, controllerName))
	return handlers
}

func (cm *ConfigMapResource) HasStatusSubresource() bool {
	return false
}
