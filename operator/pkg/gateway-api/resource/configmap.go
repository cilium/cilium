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
	registryConfig RegistryConfig
}

func NewConfigMapResource(r RegistryConfig) *ConfigMapResource {
	return &ConfigMapResource{
		ResourceType:   &corev1.ConfigMap{},
		registryConfig: r,
	}
}

// ShouldIndex - ConfigMaps should never be indexed.
func (tr *ConfigMapResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (tr *ConfigMapResource) GetIndexers(c helpers.ClientReader, logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (tr *ConfigMapResource) GetResource() client.Object {
	return tr.ResourceType
}

// ShouldWatch - ConfigMaps should always be watched.
func (tr *ConfigMapResource) ShouldWatch() bool {
	return true
}

func (tr *ConfigMapResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	handlers = append(handlers, watchhandlers.EnqueueRequestForBackendTLSPolicyConfigMap(c, logger, controllerName))
	handlers = append(handlers, watchhandlers.EnqueueRequestForFrontendTLSConfigMap(c, logger, controllerName))
	return handlers
}
