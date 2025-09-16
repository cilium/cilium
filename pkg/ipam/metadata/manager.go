// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync/atomic"

	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam"
	consts "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ManagerStoppedError struct{}

func (m *ManagerStoppedError) Error() string {
	return "ipam-metadata-manager has been stopped"
}

var ErrManagerPoolsNotSynced = errors.New("ipam-metadata-manager has not synced all pod IP pools yet")

type ResourceNotFound struct {
	Resource  string
	Name      string
	Namespace string
}

func (r *ResourceNotFound) Error() string {
	name := r.Name
	if r.Namespace != "" {
		name = r.Namespace + "/" + r.Name
	}
	return fmt.Sprintf("resource %s %q not found", r.Resource, name)
}

func (r *ResourceNotFound) Is(target error) bool {
	targetErr, ok := target.(*ResourceNotFound)
	if !ok {
		return false
	}
	if r != nil && targetErr.Resource != "" {
		return r.Resource == targetErr.Resource
	}
	return true
}

type Manager interface {
	GetIPPoolForPod(owner string, family ipam.Family) (pool string, err error)
}

type manager struct {
	logger     *slog.Logger
	db         *statedb.DB
	pods       statedb.Table[k8s.LocalPod]
	namespaces statedb.Table[k8s.Namespace]

	// compiledPools is a map of pools and their selectors that have been compiled
	// from CiliumPodIPPool resources. It is protected by a RWMutex.
	// TODO: Use stateDB instead https://github.com/cilium/cilium/pull/41688#discussion_r2371642168
	compiledPools map[string]compiledPool
	poolMu        lock.RWMutex
	// poolsSynced shows whether the manager has received a Sync event from the poolInformer.
	// GetIPPoolForPod will return an error until the poolInformer has received a Sync event.
	poolsSynced atomic.Bool
}

type compiledPool struct {
	name              string
	podSelector       slim_labels.Selector
	namespaceSelector slim_labels.Selector
	hasV4             bool
	hasV6             bool
}

func splitK8sPodName(owner string) (namespace, name string, ok bool) {
	// Require namespace/name format
	namespace, name, ok = strings.Cut(owner, "/")
	if !ok {
		return "", "", false
	}
	// Check if components are a valid namespace name and pod name
	if validation.IsDNS1123Subdomain(namespace) != nil ||
		validation.IsDNS1123Subdomain(name) != nil {
		return "", "", false
	}
	return namespace, name, true
}

func determinePoolByAnnotations(annotations map[string]string, family ipam.Family) (pool string, ok bool) {
	switch family {
	case ipam.IPv4:
		if annotations[annotation.IPAMIPv4PoolKey] != "" {
			return annotations[annotation.IPAMIPv4PoolKey], true
		} else if annotations[annotation.IPAMPoolKey] != "" {
			return annotations[annotation.IPAMPoolKey], true
		}
	case ipam.IPv6:
		if annotations[annotation.IPAMIPv6PoolKey] != "" {
			return annotations[annotation.IPAMIPv6PoolKey], true
		} else if annotations[annotation.IPAMPoolKey] != "" {
			return annotations[annotation.IPAMPoolKey], true
		}
	}

	return "", false
}

func (m *manager) GetIPPoolForPod(owner string, family ipam.Family) (pool string, err error) {
	if !m.poolsSynced.Load() {
		return "", ErrManagerPoolsNotSynced
	}
	if family != ipam.IPv6 && family != ipam.IPv4 {
		return "", fmt.Errorf("invalid IP family: %s", family)
	}

	namespace, name, ok := splitK8sPodName(owner)
	if !ok {
		m.logger.Debug(
			"pool selector: IPAM metadata request for invalid pod name, falling back to default pool",
			logfields.Owner, owner,
		)
		return ipam.PoolDefault().String(), nil
	}

	txn := m.db.ReadTxn()

	// Check annotation on pod
	pod, _, found := m.pods.Get(txn, k8s.PodByName(namespace, name))
	if !found {
		return "", &ResourceNotFound{Resource: "Pod", Namespace: namespace, Name: name}
	} else if ippool, ok := determinePoolByAnnotations(pod.Annotations, family); ok {
		m.logger.Debug("pool selector: found pool by pod annotation",
			logfields.Owner, owner,
			logfields.K8sNamespace, namespace,
			logfields.Name, name,
			logfields.PoolName, ippool,
		)
		return ippool, nil
	}

	// Check annotation on namespace
	podNamespace, _, found := m.namespaces.Get(txn, k8s.NamespaceIndex.Query(namespace))
	if !found {
		m.logger.Debug("pool selector: namespace not found",
			logfields.Owner, owner,
			logfields.K8sNamespace, namespace,
		)
		return "", &ResourceNotFound{Resource: "Namespace", Name: namespace}
	} else if ippool, ok := determinePoolByAnnotations(podNamespace.Annotations, family); ok {
		m.logger.Debug("pool selector: found pool by namespace annotation",
			logfields.Owner, owner,
			logfields.K8sNamespace, namespace,
			logfields.PoolName, ippool,
		)
		return ippool, nil
	}

	podLabels := maps.Clone(pod.Labels)
	if podLabels == nil {
		podLabels = make(map[string]string)
	}
	// Add synthetic fields for selectors
	podLabels[consts.PodNamespaceLabel] = namespace
	podLabels[consts.PodNameLabel] = name

	var matches []string
	m.poolMu.RLock()
	for _, cp := range m.compiledPools {
		if family == ipam.IPv4 && !cp.hasV4 {
			continue
		}
		if family == ipam.IPv6 && !cp.hasV6 {
			continue
		}
		// Check if pod matches the pool's podSelector (if specified)
		podMatches := cp.podSelector == nil || cp.podSelector.Matches(labels.Set(podLabels))

		// Check if namespace matches the pool's namespaceSelector (if specified)
		namespaceMatches := cp.namespaceSelector == nil || cp.namespaceSelector.Matches(labels.Set(podNamespace.Labels))

		if podMatches && namespaceMatches {
			matches = append(matches, cp.name)
		}
	}
	m.poolMu.RUnlock()

	switch len(matches) {
	case 0:
		// Check if pod or namespace requires pool match
		podRequiresMatch := pod.Annotations[annotation.IPAMRequirePoolMatch] == "true"
		namespaceRequiresMatch := podNamespace.Annotations[annotation.IPAMRequirePoolMatch] == "true"
		if podRequiresMatch || namespaceRequiresMatch {
			var annotationLocation string
			if podRequiresMatch {
				annotationLocation = "pod"
			} else {
				annotationLocation = "namespace"
			}
			return "", fmt.Errorf("no matching CiliumPodIPPool found for pod %s (family=%s) and require-pool-match annotation is set on %s", owner, family, annotationLocation)
		}
		// Fallback to default pool
		m.logger.Debug("pool selector: no matches, falling back to default pool",
			logfields.Owner, owner,
		)
		return ipam.PoolDefault().String(), nil
	case 1:
		m.logger.Debug("pool selector: found matching pool",
			logfields.Owner, owner,
			logfields.PoolName, matches[0],
		)
		return matches[0], nil
	default:
		// If multiple pools match, fail the allocation
		m.logger.Error("pool selector: multiple pools matched; refusing to choose a pool",
			logfields.Owner, owner,
			logfields.Matches, matches,
		)
		return "", fmt.Errorf("multiple CiliumPodIPPools match pod %s (family=%s): %v", owner, family, matches)
	}
}

// handlePoolEvent handles individual CiliumPodIPPool events and maintains internal selector state.
func (m *manager) handlePoolEvent(ctx context.Context, event resource.Event[*cilium_v2alpha1.CiliumPodIPPool]) error {
	defer func() {
		event.Done(nil)
	}()

	switch event.Kind {
	case resource.Sync:
		m.logger.Debug("pool watcher: pools synced")
		m.poolsSynced.Store(true)
		return nil
	case resource.Upsert:
		m.compilePool(event.Object)
	case resource.Delete:
		m.deleteCompiledPool(event.Object.Name)
	}

	m.logger.Debug("pool watcher: handled new pool event",
		logfields.PoolName, event.Object.Name,
		logfields.CompiledPools, m.getCompiledPools())
	return nil
}

func (m *manager) compilePool(p *cilium_v2alpha1.CiliumPodIPPool) {
	// Compile selectors
	var podSelector slim_labels.Selector
	var namespaceSelector slim_labels.Selector

	hasPodSelector := p.Spec.PodSelector != nil
	hasNamespaceSelector := p.Spec.NamespaceSelector != nil
	if !hasPodSelector && !hasNamespaceSelector {
		m.logger.Debug("pool watcher: pool has no pod or namespace selectors; ignoring",
			logfields.PoolName, p.Name,
		)
		m.deleteCompiledPool(p.Name)
		return
	}
	if hasPodSelector {
		sel, err := slim_meta_v1.LabelSelectorAsSelector(p.Spec.PodSelector)
		if err != nil {
			m.logger.Error("pool watcher: failed to compile podSelector for CiliumPodIPPool; ignoring selector",
				logfields.PoolName, p.Name,
				logfields.Error, err)
			return
		}
		podSelector = sel
	}

	if hasNamespaceSelector {
		sel, err := slim_meta_v1.LabelSelectorAsSelector(p.Spec.NamespaceSelector)
		if err != nil {
			m.logger.Error("pool watcher: failed to compile namespaceSelector for CiliumPodIPPool; ignoring selector",
				logfields.PoolName, p.Name,
				logfields.Error, err)
			return
		}
		namespaceSelector = sel
	}

	cp := compiledPool{
		name:              p.Name,
		podSelector:       podSelector,
		namespaceSelector: namespaceSelector,
		hasV4:             p.Spec.IPv4 != nil,
		hasV6:             p.Spec.IPv6 != nil,
	}

	m.setCompiledPool(cp)
}

func (m *manager) setCompiledPool(p compiledPool) {
	m.poolMu.Lock()
	m.compiledPools[p.name] = p
	m.poolMu.Unlock()
}

func (m *manager) deleteCompiledPool(name string) {
	m.poolMu.Lock()
	delete(m.compiledPools, name)
	m.poolMu.Unlock()
}

func (m *manager) getCompiledPool(name string) (compiledPool, bool) {
	m.poolMu.RLock()
	defer m.poolMu.RUnlock()
	cp, ok := m.compiledPools[name]
	return cp, ok
}

func (m *manager) getCompiledPools() map[string]compiledPool {
	m.poolMu.RLock()
	defer m.poolMu.RUnlock()
	return maps.Clone(m.compiledPools)
}
