// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespace

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

type managerParams struct {
	cell.In

	Logger     *slog.Logger
	Config     Config
	Namespaces resource.Resource[*slim_corev1.Namespace]
	Lifecycle  cell.Lifecycle
}

type Manager interface {
	IsGlobalNamespaceByName(ns string) (bool, error)
	IsGlobalNamespaceByObject(ns *slim_corev1.Namespace) bool
}

type manager struct {
	logger *slog.Logger
	cfg    Config
	store  resource.Store[*slim_corev1.Namespace]
}

func newManager(params managerParams) *manager {
	m := &manager{
		logger: params.Logger,
		cfg:    params.Config,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			store, err := params.Namespaces.Store(ctx)
			if err != nil {
				return fmt.Errorf("failed to get namespace store: %w", err)
			}
			m.store = store
			return nil
		},
	})

	return m
}

// IsGlobalNamespaceByObject determines whether the given namespace should be treated as a global
// namespace based on its annotations and the provided configuration.
func (m *manager) IsGlobalNamespaceByObject(ns *slim_corev1.Namespace) bool {
	if ns == nil {
		return false
	}
	// Get annotations for the namespace.
	// If annotated with "clustermesh.cilium.io/global", supercede the default config.
	annotations := ns.GetAnnotations()
	if value, ok := annotations[annotation.GlobalNamespace]; ok {
		return strings.ToLower(value) == "true"
	}
	// If the annotation is not present, fall back to the default config.
	return m.cfg.GlobalNamespacesByDefault
}

// IsGlobalNamespaceByName determines whether the namespace with the given name should be treated
// as a global namespace based on its annotations and the provided configuration.
// It retrieves the namespace object from the named resource store embedded in manager ob.
func (m *manager) IsGlobalNamespaceByName(ns string) (bool, error) {
	if m.store == nil {
		return false, fmt.Errorf("namespace store not initialized")
	}

	obj, exists, err := m.store.GetByKey(resource.Key{Name: ns})
	if err != nil {
		return false, fmt.Errorf("error getting namespace from store: %w", err)
	}
	if !exists {
		return false, fmt.Errorf("namespace %s does not exist in store", ns)
	}
	return m.IsGlobalNamespaceByObject(obj), nil
}
