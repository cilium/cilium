// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"fmt"
	"log/slog"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/store"
)

// meshPodInformer uses the ClusterServices to create fake pods based on each backends.
// This applies the labels `mesh.cilium.io/service-key` and `mesh.cilium.io/service-cluster`
// that corresponds to fake services created by meshServiceInformer.
type meshPodInformer struct {
	dummyInformer

	logger             *slog.Logger
	globalServiceCache *common.GlobalServiceCache
	handler            cache.ResourceEventHandler
}

func newMeshPodInformer(logger *slog.Logger, globalServiceCache *common.GlobalServiceCache) *meshPodInformer {
	return &meshPodInformer{
		dummyInformer:      dummyInformer{name: "meshPodInformer", logger: logger},
		globalServiceCache: globalServiceCache,
	}
}

func getContainerPorts(portConfig store.PortConfiguration) []v1.ContainerPort {
	ports := []v1.ContainerPort{}
	for name, l4Addr := range portConfig {
		ports = append(ports, v1.ContainerPort{
			Name:          name,
			ContainerPort: int32(l4Addr.Port),
			Protocol:      v1.Protocol(l4Addr.Protocol),
		})
	}
	return ports
}

func podObjectMeta(name string, clusterSvc *store.ClusterService) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: clusterSvc.Namespace,
		Labels: map[string]string{
			meshServiceNameLabel:    clusterSvc.Name,
			meshServiceClusterLabel: clusterSvc.Cluster,
		},
	}
}

func podFromSingleAddr(addr string, portConfig store.PortConfiguration, clusterSvc *store.ClusterService) *v1.Pod {
	return &v1.Pod{
		// The custom TypeMeta here is only used in logging inside the endpointslice reconciler
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io",
			Kind:       "store.ClusterService",
		},
		ObjectMeta: podObjectMeta("fake-pod-"+addr, clusterSvc),
		Spec: v1.PodSpec{
			NodeName:  clusterSvc.Cluster,
			Hostname:  clusterSvc.Hostnames[addr],
			Subdomain: clusterSvc.Name + "-" + clusterSvc.Cluster,
			Containers: []v1.Container{{
				Ports: getContainerPorts(portConfig),
			}},
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
			Conditions: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionTrue},
			},
			PodIPs: []v1.PodIP{{IP: addr}},
		},
	}
}

func validateSelector(reqs labels.Requirements) (string, string, error) {
	var name *string
	var cluster *string

	if len(reqs) != 2 {
		goto err
	}

	for _, req := range reqs {
		if req.Values().Len() != 1 || req.Operator() != selection.Equals {
			goto err
		}

		if req.Key() == meshServiceNameLabel {
			if name != nil {
				goto err
			}
			name = &req.Values().List()[0]
		} else if req.Key() == meshServiceClusterLabel {
			if cluster != nil {
				goto err
			}
			cluster = &req.Values().List()[0]
		}
	}

	if name == nil || cluster == nil {
		goto err
	}

	return *name, *cluster, nil

err:
	return "", "", fmt.Errorf("meshPodInformer only supports listing with both service name and cluster as requirements: %s", reqs)
}

type meshPodLister struct {
	informer  *meshPodInformer
	namespace string
}

func (l meshPodLister) List(selector labels.Selector) ([]*v1.Pod, error) {
	reqs, _ := selector.Requirements()
	name, cluster, err := validateSelector(reqs)
	if err != nil {
		return nil, err
	}

	clusterSvc := l.informer.globalServiceCache.GetService(types.NamespacedName{Name: name, Namespace: l.namespace}, cluster)
	if clusterSvc == nil {
		return nil, nil
	}

	pods := make([]*v1.Pod, 0, len(clusterSvc.Backends))
	for addr, portConfig := range clusterSvc.Backends {
		pods = append(pods, podFromSingleAddr(addr, portConfig, clusterSvc))
	}
	return pods, nil
}

func (i *meshPodInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	i.handler = handler
	return i, nil
}

func (i *meshPodInformer) onClusterServiceUpdate(clusterSvc *store.ClusterService) {
	if i.handler == nil {
		return
	}

	// We just need to notify the controller that there was an update so that
	// the update on the related service + cluster is queued.
	// The object sent here is not used and the type of event also doesn't matter.
	i.handler.OnAdd(
		&v1.Pod{
			ObjectMeta: podObjectMeta(
				"dummy-notification-"+clusterSvc.Name+"-"+clusterSvc.Namespace+"-"+clusterSvc.Cluster,
				clusterSvc,
			),
		},
		false)
}

func (i *meshPodInformer) onClusterServiceDelete(clusterSvc *store.ClusterService) {
	i.onClusterServiceUpdate(clusterSvc)
}

func (i meshPodInformer) HasSynced() bool {
	// Controller is launched only after cluster mesh has been fully synced
	// so we always return true here
	return true
}

func (i *meshPodInformer) Pods(namespace string) listersv1.PodNamespaceLister {
	return &meshPodLister{
		informer: i, namespace: namespace,
	}
}
func (i *meshPodInformer) Informer() cache.SharedIndexInformer {
	return i
}
func (i *meshPodInformer) Lister() listersv1.PodLister {
	return i
}

func (i meshPodLister) Get(name string) (*v1.Pod, error) {
	i.informer.logger.Error("called not implemented function meshPodLister.Get")
	return nil, nil
}
func (i meshPodInformer) List(selector labels.Selector) ([]*v1.Pod, error) {
	i.logger.Error("called not implemented function meshPodInformer.Get")
	return nil, nil
}
