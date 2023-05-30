// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"sync/atomic"

	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

func (k *K8sWatcher) namespacesInit() {
	apiGroup := k8sAPIGroupNamespaceV1Core

	var synced atomic.Bool
	synced.Store(false)

	k.blockWaitGroupToSyncResources(
		k.stop,
		nil,
		func() bool { return synced.Load() },
		apiGroup,
	)
	k.k8sAPIGroups.AddAPI(apiGroup)

	nsUpdater := namespaceUpdater{
		oldLabels:       make(map[string]labels.Labels),
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
					k.K8sEventProcessed(metricNS, resources.MetricUpdate, err == nil)
				}
				event.Done(err)
			}
		}
	}()
}

type namespaceUpdater struct {
	oldLabels map[string]labels.Labels

	endpointManager endpointManager
}

func getNamespaceLabels(ns *slim_corev1.Namespace) labels.Labels {
	labelMap := map[string]string{}
	for k, v := range ns.GetLabels() {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}

func (u *namespaceUpdater) update(newNS *slim_corev1.Namespace) error {
	oldLabels := u.oldLabels[newNS.Name]
	newLabels := getNamespaceLabels(newNS)

	oldIdtyLabels, _ := labelsfilter.Filter(oldLabels)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

	// Do not perform any other operations the the old labels are the same as
	// the new labels
	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
		return nil
	}

	eps := u.endpointManager.GetEndpoints()
	failed := false
	for _, ep := range eps {
		epNS := ep.GetK8sNamespace()
		if newNS.Name == epNS {
			err := ep.ModifyIdentityLabels(newIdtyLabels, oldIdtyLabels)
			if err != nil {
				log.WithError(err).WithField(logfields.EndpointID, ep.ID).
					Warningf("unable to update endpoint with new namespace labels")
				failed = true
			}
		}
	}
	if failed {
		return errors.New("unable to update some endpoints with new namespace labels")
	}
	return nil
}

// GetCachedNamespace returns a namespace from the local store.
func (k *K8sWatcher) GetCachedNamespace(namespace string) (*slim_corev1.Namespace, error) {
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
