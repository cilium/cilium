// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type ServiceImportResource struct {
	ResourceType   *mcsapiv1beta1.ServiceImport
	registryConfig helpers.ResourceConfig
}

func NewServiceImportResource(r helpers.ResourceConfig) *ServiceImportResource {
	return &ServiceImportResource{
		ResourceType:   &mcsapiv1beta1.ServiceImport{},
		registryConfig: r,
	}
}

// ShouldIndex - ServiceImports should never be indexed.
func (si *ServiceImportResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (si *ServiceImportResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (si *ServiceImportResource) GetResource() client.Object {
	return si.ResourceType
}

// ShouldWatch - ServiceImports should always be watched if they are present in the cluster.
func (si *ServiceImportResource) ShouldWatch() bool {
	return si.registryConfig.IncludeServiceImports
}

func (si *ServiceImportResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	if si.registryConfig.IncludeServiceImports {
		handlers = append(handlers, watchhandlers.EnqueueRequestForBackendServiceImport(c, logger, controllerName))
	}

	return handlers
}

func (si *ServiceImportResource) HasStatusSubresource() bool {
	return false
}
