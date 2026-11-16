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

type NamespaceResource struct {
	ResourceType   *corev1.Namespace
	registryConfig helpers.ResourceConfig
}

func NewNamespaceResource(r helpers.ResourceConfig) *NamespaceResource {
	return &NamespaceResource{
		ResourceType:   &corev1.Namespace{},
		registryConfig: r,
	}
}

// ShouldIndex - Namespaces should never be indexed.
func (ns *NamespaceResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (ns *NamespaceResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (ns *NamespaceResource) GetResource() client.Object {
	return ns.ResourceType
}

// ShouldWatch - Namespaces should always be watched.
func (ns *NamespaceResource) ShouldWatch() bool {
	return true
}

func (ns *NamespaceResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	handlers = append(handlers, watchhandlers.EnqueueRequestForAllowedNamespace(c, logger))
	return handlers
}

func (ns *NamespaceResource) HandleStatus() bool {
	return false
}
