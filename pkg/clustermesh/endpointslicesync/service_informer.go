// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync/atomic"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

const (
	meshServiceNameLabel    = "mesh.cilium.io/service-name"
	meshServiceClusterLabel = "mesh.cilium.io/service-cluster"
)

// meshServiceInformer uses the ClusterServices to pass fake services to the controllers
// based on the services in the mesh.
// Those services will be named with this form `$svcName-$clusterName` and contains
// a mcsapi source cluster label so that the underlying endpointslice will
// be (almost) correct. We also have a meshClient that overrides some endpointslice
// methods to fix back the service label name.
// The selector labels are always `mesh.cilium.io/service-key` and `mesh.cilium.io/service-cluster`
// so that the meshPodInformer can use that for his labels.
type meshServiceInformer struct {
	dummyInformer

	logger             *slog.Logger
	globalServiceCache *common.GlobalServiceCache
	services           resource.Resource[*slim_corev1.Service]
	serviceStore       resource.Store[*slim_corev1.Service]
	meshNodeInformer   *meshNodeInformer

	servicesSynced atomic.Bool
	handler        cache.ResourceEventHandler
}

func newNotFoundError(message string) *errors.StatusError {
	return &errors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Reason:  metav1.StatusReasonNotFound,
		Message: message,
	}}
}

func doesServiceSyncEndpointSlice(svc *slim_corev1.Service) bool {
	value, ok := annotation.Get(svc, annotation.GlobalService)
	if !ok || strings.ToLower(value) != "true" {
		return false
	}

	value, ok = annotation.Get(svc, annotation.GlobalServiceSyncEndpointSlices)
	if !ok {
		// If the service is headless we sync the EndpointSlice by default
		return svc.Spec.ClusterIP == v1.ClusterIPNone
	}
	return strings.ToLower(value) == "true"
}

func (i *meshServiceInformer) refreshAllCluster(svc *slim_corev1.Service) {
	if i.handler == nil {
		// We don't really need to return an error here as this means that the EndpointSlice controller
		// has not started yet and the controller will resync the initial state anyway
		return
	}

	if globalSvc := i.globalServiceCache.GetGlobalService(types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}); globalSvc != nil {
		for _, clusterSvc := range globalSvc.ClusterServices {
			// It doesn't matter which event we trigger as the controller ends up always
			// queuing the update the same way regardless of the event.
			if svc, err := i.clusterSvcToSvc(clusterSvc, true); err == nil {
				i.handler.OnAdd(svc, false)
			}
		}
	}
}

func newMeshServiceInformer(
	logger *slog.Logger,
	globalServiceCache *common.GlobalServiceCache,
	services resource.Resource[*slim_corev1.Service],
	meshNodeInformer *meshNodeInformer,
) *meshServiceInformer {
	return &meshServiceInformer{
		dummyInformer:      dummyInformer{name: "meshServiceInformer", logger: logger},
		logger:             logger,
		globalServiceCache: globalServiceCache,
		services:           services,
		meshNodeInformer:   meshNodeInformer,
	}
}

// toKubeServicePort use the clusterSvc to get a list of ServicePort to build
// the kubernetes (non slim) Service. Note that we intentionally not use the local
// Service to build the port list so that we don't change the remote Cluster Service port
// list. Also targetPort might be targeting a named port and we currently don't
// sync the container ports names.
func toKubeServicePort(clusterSvc *store.ClusterService) []v1.ServicePort {
	// Merge all the port config into one to get all the possible ports
	globalPortConfig := store.PortConfiguration{}
	for _, portConfig := range clusterSvc.Backends {
		maps.Copy(globalPortConfig, portConfig)
	}

	// Get the ServicePort from the PortConfig
	regularServicePorts := make([]v1.ServicePort, 0, len(globalPortConfig))
	for name, l4Addr := range globalPortConfig {
		regularServicePorts = append(regularServicePorts, v1.ServicePort{
			Name:       name,
			Protocol:   v1.Protocol(l4Addr.Protocol),
			TargetPort: intstr.FromInt(int(l4Addr.Port)),
		})
	}
	return regularServicePorts
}

// toKubeIpFamilies convert the ipFamilies from the Cilium slim Service type
// to the regular Kubernetes Service type
func toKubeIpFamilies(ipFamilies []slim_corev1.IPFamily) []v1.IPFamily {
	regularIpFamilies := make([]v1.IPFamily, len(ipFamilies))
	for i, ipFamily := range ipFamilies {
		regularIpFamilies[i] = v1.IPFamily(ipFamily)
	}
	return regularIpFamilies
}

func (i *meshServiceInformer) clusterSvcToSvc(clusterSvc *store.ClusterService, force bool) (*v1.Service, error) {
	if i.serviceStore == nil {
		return nil, fmt.Errorf("service informer not started yet")
	}

	svc, exists, err := i.serviceStore.GetByKey(resource.Key{Name: clusterSvc.Name, Namespace: clusterSvc.Namespace})
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, newNotFoundError(fmt.Sprintf("service '%s' not found", clusterSvc.NamespaceServiceName()))
	}

	if !force && !doesServiceSyncEndpointSlice(svc) {
		return nil, newNotFoundError(fmt.Sprintf("service '%s' does not have sync endpoint slice annotation", clusterSvc.NamespaceServiceName()))
	}

	labels := maps.Clone(svc.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	maps.Copy(labels, map[string]string{
		meshRealServiceNameLabel:          clusterSvc.Name,
		mcsapiv1alpha1.LabelSourceCluster: clusterSvc.Cluster,
	})

	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterSvc.Name + "-" + clusterSvc.Cluster,
			UID:       svc.UID,
			Namespace: clusterSvc.Namespace,
			Labels:    labels,
		},
		Spec: v1.ServiceSpec{
			Ports: toKubeServicePort(clusterSvc),
			Selector: map[string]string{
				meshServiceNameLabel:    clusterSvc.Name,
				meshServiceClusterLabel: clusterSvc.Cluster,
			},
			ClusterIP:  svc.Spec.ClusterIP,
			ClusterIPs: svc.Spec.ClusterIPs,
			Type:       v1.ServiceType(svc.Spec.Type),
			IPFamilies: toKubeIpFamilies(svc.Spec.IPFamilies),
		},
	}, nil
}

type meshServiceLister struct {
	informer  *meshServiceInformer
	namespace string
}

// List returns the matrix of all the local services and all the remote clusters.
// This is not similar to what does the Get method. For instance, List may returns
// services that could not be found on a call to the Get method.
// By doing that we can ensure that the controller reconciliation is called
// on every possible remote services especially the one that are deleted while
// we still have some EndpointSlices locally (which won't be cleared by the
// OwnerReference mechanism since our actual local service is not deleted).
func (l meshServiceLister) List(selector labels.Selector) ([]*v1.Service, error) {
	reqs, _ := selector.Requirements()
	if !selector.Empty() {
		return nil, fmt.Errorf("meshServiceInformer only supports listing everything as requirements: %s", reqs)
	}

	originalSvcs, err := l.informer.serviceStore.ByIndex(k8s.NamespaceIndex, l.namespace)
	if err != nil {
		return nil, err
	}

	clusters := l.informer.meshNodeInformer.ListClusters()
	var svcs []*v1.Service
	for _, svc := range originalSvcs {
		for _, cluster := range clusters {
			dummyClusterSvc := &store.ClusterService{
				Cluster:   cluster,
				Name:      svc.Name,
				Namespace: l.namespace,
			}
			if svc, err := l.informer.clusterSvcToSvc(dummyClusterSvc, false); err == nil {
				svcs = append(svcs, svc)
			}
		}
	}

	return svcs, nil
}

// Get attempts to retrieve a *store.ClusterService object by separating the
// service name in the full service name and then convert it to a regular
// Kubernetes Service.
func (l meshServiceLister) Get(name string) (*v1.Service, error) {
	// TODO: We could try to use an illegal character to separate the service name and
	// the cluster name
	posClusterName := len(name)
	for {
		posClusterName = strings.LastIndex(name[:posClusterName], "-")
		if posClusterName == -1 {
			break
		}

		svcName := name[:posClusterName]
		clusterName := name[posClusterName+1:]
		clusterSvc := l.informer.globalServiceCache.GetService(types.NamespacedName{Name: svcName, Namespace: l.namespace}, clusterName)

		if clusterSvc == nil {
			continue
		}
		return l.informer.clusterSvcToSvc(clusterSvc, false)
	}

	return nil, newNotFoundError(fmt.Sprintf("cannot find cluster service with name '%s'", name))
}

func (i *meshServiceInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	i.handler = handler
	return i, nil
}

func (i *meshServiceInformer) HasSynced() bool {
	return i.servicesSynced.Load()
}

func (i *meshServiceInformer) Start(ctx context.Context) error {
	var err error
	if i.serviceStore, err = i.services.Store(ctx); err != nil {
		return err
	}

	go func() {
		for event := range i.services.Events(ctx) {
			switch event.Kind {
			case resource.Sync:
				i.logger.Debug("Local services are synced")
				i.servicesSynced.Store(true)
			case resource.Upsert:
				i.refreshAllCluster(event.Object)
			case resource.Delete:
				i.refreshAllCluster(event.Object)
			}
			event.Done(nil)
		}
	}()
	return nil
}

func (i *meshServiceInformer) Services(namespace string) listersv1.ServiceNamespaceLister {
	return &meshServiceLister{informer: i, namespace: namespace}
}

func (i *meshServiceInformer) Informer() cache.SharedIndexInformer {
	return i
}

func (i *meshServiceInformer) Lister() listersv1.ServiceLister {
	return i
}

func (i *meshServiceInformer) List(selector labels.Selector) (ret []*v1.Service, err error) {
	i.logger.Error("called not implemented function meshServiceInformer.List")
	return nil, nil
}
