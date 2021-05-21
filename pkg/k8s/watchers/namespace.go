// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watchers

import (
	"errors"
	"sync"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"

	v1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) namespacesInit(k8sClient kubernetes.Interface, asyncControllers *sync.WaitGroup) {
	namespaceStore, namespaceController := informer.NewInformer(
		cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"namespaces", v1.NamespaceAll, fields.Everything()),
		&slim_corev1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{
			// AddFunc does not matter since the endpoint will fetch
			// namespace labels when the endpoint is created
			// DelFunc does not matter since, when a namespace is deleted, all
			// pods belonging to that namespace are also deleted.
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricNS, metricUpdate, valid, equal) }()
				if oldNS := k8s.ObjToV1Namespace(oldObj); oldNS != nil {
					if newNS := k8s.ObjToV1Namespace(newObj); newNS != nil {
						valid = true
						if oldNS.DeepEqual(newNS) {
							equal = true
							return
						}

						err := k.updateK8sV1Namespace(oldNS, newNS)
						k.K8sEventProcessed(metricNS, metricUpdate, err == nil)
					}
				}
			},
		},
		nil,
	)

	k.namespaceStore = namespaceStore
	k.blockWaitGroupToSyncResources(wait.NeverStop, nil, namespaceController.HasSynced, k8sAPIGroupNamespaceV1Core)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupNamespaceV1Core)
	asyncControllers.Done()
	namespaceController.Run(wait.NeverStop)
}

func (k *K8sWatcher) updateK8sV1Namespace(oldNS, newNS *slim_corev1.Namespace) error {
	oldNSLabels := map[string]string{}
	newNSLabels := map[string]string{}

	for k, v := range oldNS.GetLabels() {
		oldNSLabels[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	for k, v := range newNS.GetLabels() {
		newNSLabels[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}

	oldLabels := labels.Map2Labels(oldNSLabels, labels.LabelSourceK8s)
	newLabels := labels.Map2Labels(newNSLabels, labels.LabelSourceK8s)

	oldIdtyLabels, _ := labelsfilter.Filter(oldLabels)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

	// Do not perform any other operations the the old labels are the same as
	// the new labels
	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
		return nil
	}

	eps := k.endpointManager.GetEndpoints()
	failed := false
	for _, ep := range eps {
		epNS := ep.GetK8sNamespace()
		if oldNS.Name == epNS {
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
	<-k.controllersStarted
	k.WaitForCacheSync(k8sAPIGroupNamespaceV1Core)
	nsName := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: namespace,
		},
	}
	namespaceInterface, exists, err := k.namespaceStore.Get(nsName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8s_errors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "namespace",
		}, namespace)
	}
	return namespaceInterface.(*slim_corev1.Namespace).DeepCopy(), nil
}
