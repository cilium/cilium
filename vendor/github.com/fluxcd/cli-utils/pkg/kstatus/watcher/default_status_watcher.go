// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"time"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/clusterreader"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/statusreaders"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
)

// DefaultStatusWatcher reports on status updates to a set of objects.
//
// Use NewDefaultStatusWatcher to build a DefaultStatusWatcher with default settings.
type DefaultStatusWatcher struct {
	// DynamicClient is used to watch of resource objects.
	DynamicClient dynamic.Interface

	// Mapper is used to map from GroupKind to GroupVersionKind.
	Mapper meta.RESTMapper

	// ResyncPeriod is how often the objects are retrieved to re-synchronize,
	// in case any events were missed.
	ResyncPeriod time.Duration

	// StatusReader specifies a custom implementation of the
	// engine.StatusReader interface that will be used to compute reconcile
	// status for resource objects.
	StatusReader engine.StatusReader

	// ClusterReader is used to look up generated objects on-demand.
	// Generated objects (ex: Deployment > ReplicaSet > Pod) are sometimes
	// required for computing parent object status, to compensate for
	// controllers that aren't following status conventions.
	ClusterReader engine.ClusterReader
}

var _ StatusWatcher = &DefaultStatusWatcher{}

// NewDefaultStatusWatcher constructs a DynamicStatusWatcher with defaults
// chosen for general use. If you need different settings, consider building a
// DynamicStatusWatcher directly.
func NewDefaultStatusWatcher(dynamicClient dynamic.Interface, mapper meta.RESTMapper) *DefaultStatusWatcher {
	return &DefaultStatusWatcher{
		DynamicClient: dynamicClient,
		Mapper:        mapper,
		ResyncPeriod:  1 * time.Hour,
		StatusReader:  statusreaders.NewDefaultStatusReader(mapper),
		ClusterReader: &clusterreader.DynamicClusterReader{
			DynamicClient: dynamicClient,
			Mapper:        mapper,
		},
	}
}

// Watch the cluster for changes made to the specified objects.
// Returns an event channel on which these updates (and errors) will be reported.
// Each update event includes the computed status of the object.
func (w *DefaultStatusWatcher) Watch(ctx context.Context, ids object.ObjMetadataSet, opts Options) <-chan event.Event {
	strategy := opts.RESTScopeStrategy
	if strategy == RESTScopeAutomatic {
		strategy = autoSelectRESTScopeStrategy(ids)
	}

	var scope meta.RESTScope
	var targets []GroupKindNamespace
	switch strategy {
	case RESTScopeRoot:
		scope = meta.RESTScopeRoot
		targets = rootScopeGKNs(ids)
		klog.V(3).Infof("DynamicStatusWatcher starting in root-scoped mode (targets: %d)", len(targets))
	case RESTScopeNamespace:
		scope = meta.RESTScopeNamespace
		targets = namespaceScopeGKNs(ids)
		klog.V(3).Infof("DynamicStatusWatcher starting in namespace-scoped mode (targets: %d)", len(targets))
	default:
		return handleFatalError(fmt.Errorf("invalid RESTScopeStrategy: %v", strategy))
	}

	informer := &ObjectStatusReporter{
		InformerFactory: NewDynamicInformerFactory(w.DynamicClient, w.ResyncPeriod),
		Mapper:          w.Mapper,
		StatusReader:    w.StatusReader,
		ClusterReader:   w.ClusterReader,
		Targets:         targets,
		ObjectFilter:    &AllowListObjectFilter{AllowList: ids},
		RESTScope:       scope,
	}
	return informer.Start(ctx)
}

func handleFatalError(err error) <-chan event.Event {
	eventCh := make(chan event.Event)
	go func() {
		defer close(eventCh)
		eventCh <- event.Event{
			Type:  event.ErrorEvent,
			Error: err,
		}
	}()
	return eventCh
}

func autoSelectRESTScopeStrategy(ids object.ObjMetadataSet) RESTScopeStrategy {
	if len(uniqueNamespaces(ids)) > 1 {
		return RESTScopeRoot
	}
	return RESTScopeNamespace
}

func rootScopeGKNs(ids object.ObjMetadataSet) []GroupKindNamespace {
	gks := uniqueGKs(ids)
	targets := make([]GroupKindNamespace, len(gks))
	for i, gk := range gks {
		targets[i] = GroupKindNamespace{
			Group:     gk.Group,
			Kind:      gk.Kind,
			Namespace: "",
		}
	}
	return targets
}

func namespaceScopeGKNs(ids object.ObjMetadataSet) []GroupKindNamespace {
	return uniqueGKNs(ids)
}

// uniqueGKNs returns a set of unique GroupKindNamespaces from a set of object identifiers.
func uniqueGKNs(ids object.ObjMetadataSet) []GroupKindNamespace {
	gknMap := make(map[GroupKindNamespace]struct{})
	for _, id := range ids {
		gkn := GroupKindNamespace{Group: id.GroupKind.Group, Kind: id.GroupKind.Kind, Namespace: id.Namespace}
		gknMap[gkn] = struct{}{}
	}
	gknList := make([]GroupKindNamespace, 0, len(gknMap))
	for gk := range gknMap {
		gknList = append(gknList, gk)
	}
	return gknList
}

// uniqueGKs returns a set of unique GroupKinds from a set of object identifiers.
func uniqueGKs(ids object.ObjMetadataSet) []schema.GroupKind {
	gkMap := make(map[schema.GroupKind]struct{})
	for _, id := range ids {
		gkn := schema.GroupKind{Group: id.GroupKind.Group, Kind: id.GroupKind.Kind}
		gkMap[gkn] = struct{}{}
	}
	gkList := make([]schema.GroupKind, 0, len(gkMap))
	for gk := range gkMap {
		gkList = append(gkList, gk)
	}
	return gkList
}

func uniqueNamespaces(ids object.ObjMetadataSet) []string {
	nsMap := make(map[string]struct{})
	for _, id := range ids {
		nsMap[id.Namespace] = struct{}{}
	}
	nsList := make([]string, 0, len(nsMap))
	for ns := range nsMap {
		nsList = append(nsList, ns)
	}
	return nsList
}
