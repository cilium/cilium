// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

type k8sNamespaceWatcherParams struct {
	cell.In

	Logger *slog.Logger

	Resources         agentK8s.Resources
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups

	EndpointManager endpointmanager.EndpointManager
}

func newK8sNamespaceWatcher(params k8sNamespaceWatcherParams) *K8sNamespaceWatcher {
	return &K8sNamespaceWatcher{
		logger:            params.Logger,
		k8sResourceSynced: params.K8sResourceSynced,
		k8sAPIGroups:      params.K8sAPIGroups,
		resources:         params.Resources,
		endpointManager:   params.EndpointManager,
		stop:              make(chan struct{}),
	}
}

type K8sNamespaceWatcher struct {
	logger *slog.Logger

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources
	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups
	resources    agentK8s.Resources

	endpointManager endpointManager

	stop chan struct{}
}

func (k *K8sNamespaceWatcher) namespacesInit() {
	apiGroup := resources.K8sAPIGroupNamespaceV1Core

	var synced atomic.Bool

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		k.stop,
		nil,
		func() bool { return synced.Load() },
		apiGroup,
	)
	k.k8sAPIGroups.AddAPI(apiGroup)

	nsUpdater := namespaceUpdater{
		logger:          k.logger,
		oldIdtyLabels:   make(map[string]labels.Labels),
		endpointManager: k.endpointManager,
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := k.resources.Namespaces.Events(ctx)

	go func() {
		for {
			select {
			case <-k.stop:
				cancel()
			case event, ok := <-events:
				if !ok {
					return
				}
				var err error
				switch event.Kind {
				case resource.Sync:
					synced.Store(true)
				case resource.Upsert:
					err = nsUpdater.update(event.Object)
				}
				event.Done(err)
			}
		}
	}()
}

func (k *K8sNamespaceWatcher) stopWatcher() {
	close(k.stop)
}

type namespaceUpdater struct {
	logger *slog.Logger

	oldIdtyLabels map[string]labels.Labels

	endpointManager endpointManager
}

func getNamespaceLabels(ns *slim_corev1.Namespace) labels.Labels {
	lbls := ns.GetLabels()
	labelMap := make(map[string]string, len(lbls))
	for k, v := range lbls {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}

func (u *namespaceUpdater) update(newNS *slim_corev1.Namespace) error {
	newLabels := getNamespaceLabels(newNS)

	oldIdtyLabels := u.oldIdtyLabels[newNS.Name]
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

	// Do not perform any other operations if the old labels are the same as
	// the new labels.
	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
		return nil
	}

	eps := u.endpointManager.GetEndpoints()
	failed := false
	for _, ep := range eps {
		epNS := ep.GetK8sNamespace()
		if newNS.Name == epNS {
			err := ep.ModifyIdentityLabels(labels.LabelSourceK8s, newIdtyLabels, oldIdtyLabels)
			if err != nil {
				u.logger.Warn(
					"unable to update endpoint with new identity labels from namespace labels",
					logfields.Error, err,
					logfields.EndpointID, ep.ID,
				)
				failed = true
			}
		}
	}
	if failed {
		return errors.New("unable to update some endpoints with new namespace labels")
	}
	u.oldIdtyLabels[newNS.Name] = newIdtyLabels
	return nil
}

// GetCachedNamespace returns a namespace from the local store.
func (k *K8sNamespaceWatcher) GetCachedNamespace(namespace string) (*slim_corev1.Namespace, error) {
	nsName := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}

	store, err := k.resources.Namespaces.Store(context.Background())
	if err != nil {
		return nil, err
	}
	ns, exists, err := store.Get(nsName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8s_errors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "namespace",
		}, namespace)
	}
	return ns.DeepCopy(), nil
}
