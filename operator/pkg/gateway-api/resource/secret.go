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

type SecretResource struct {
	ResourceType   *corev1.Secret
	registryConfig helpers.ResourceConfig
}

func NewSecretResource(r helpers.ResourceConfig) *SecretResource {
	return &SecretResource{
		ResourceType:   &corev1.Secret{},
		registryConfig: r,
	}
}

// ShouldIndex - Secrets should never be indexed.
func (s *SecretResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (s *SecretResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (s *SecretResource) GetResource() client.Object {
	return s.ResourceType
}

// ShouldWatch - Secrets should always be watched.
func (s *SecretResource) ShouldWatch() bool {
	return true
}

func (s *SecretResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	handlers = append(handlers, watchhandlers.EnqueueRequestForTLSSecret(c, controllerName, logger))
	return handlers
}

func (s *SecretResource) HandleStatus() bool {
	return false
}
