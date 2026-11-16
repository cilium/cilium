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

type NodeResource struct {
	ResourceType   *corev1.Node
	registryConfig helpers.ResourceConfig
}

func NewNodeResource(r helpers.ResourceConfig) *NodeResource {
	return &NodeResource{
		ResourceType:   &corev1.Node{},
		registryConfig: r,
	}
}

// ShouldIndex - Nodes should never be indexed.
func (n *NodeResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (n *NodeResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (n *NodeResource) GetResource() client.Object {
	return n.ResourceType
}

// ShouldWatch - Nodes should always be watched.
func (n *NodeResource) ShouldWatch() bool {
	return true
}

func (n *NodeResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	handlers = append(handlers, watchhandlers.EnqueueRequestForNodes(c, logger, n.registryConfig.OwningGatewayLabel, controllerName))
	return handlers
}

func (n *NodeResource) HandleStatus() bool {
	return false
}
