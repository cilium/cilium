// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type BackendTLSPolicyResource struct {
	ResourceType   *gatewayv1.BackendTLSPolicy
	registryConfig RegistryConfig
}

func NewBackendTLSPolicyResource(r RegistryConfig) *BackendTLSPolicyResource {
	return &BackendTLSPolicyResource{
		ResourceType:   &gatewayv1.BackendTLSPolicy{},
		registryConfig: r,
	}
}

// ShouldIndex - BackendTLSPolicies should always be indexed.
func (tr *BackendTLSPolicyResource) ShouldIndex() bool {
	return true
}

func (tr *BackendTLSPolicyResource) GetIndexers(c helpers.ClientReader, logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)

	// First, set up the simple indexers
	returnMap[indexers.BackendTLSPolicyConfigMapIndex] = indexers.IndexBTLSPolicyByConfigMap

	return returnMap
}

func (tr *BackendTLSPolicyResource) GetResource() client.Object {
	return tr.ResourceType
}

// ShouldWatch - BackendTLSPolicys should always be watched.
func (tr *BackendTLSPolicyResource) ShouldWatch() bool {
	return true
}

func (tr *BackendTLSPolicyResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.TypedEventHandler[client.Object, reconcile.Request] {
	return []handler.TypedEventHandler[client.Object, reconcile.Request]{watchhandlers.EnqueueRequestForBackendTLSPolicy(c, logger, controllerName)}
}
