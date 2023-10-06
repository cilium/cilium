// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"

	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	discoveryv1 "k8s.io/client-go/kubernetes/typed/discovery/v1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	meshRealServiceNameLabel = "mesh.cilium.io/real-service-name"
)

// meshClient override a few EndpointSlice methods to add/remove "hacks" on EndpointSlice.
// This is necessary because the service informer passed to the controller will create
// fake services with this form `$svcName-$clusterName` whereas the actual Service
// doesn't contain the $clusterName. So this client is used to intercept
// list/watch calls to also make sure that we fake the service name referenced
// by EndpoinSlices and will revert those changes at the create/update level to make
// sure that the correct data is written to the Kubernetes API.
type meshClient struct {
	k8sClient.Clientset
}

func (c meshClient) DiscoveryV1() discoveryv1.DiscoveryV1Interface {
	return meshClientDiscoveryV1{c.Clientset.DiscoveryV1()}
}

type meshClientDiscoveryV1 struct {
	discoveryv1.DiscoveryV1Interface
}

func (c meshClientDiscoveryV1) EndpointSlices(namespace string) discoveryv1.EndpointSliceInterface {
	return meshClientEndpointSlice{c.DiscoveryV1Interface.EndpointSlices(namespace)}
}

type meshClientEndpointSlice struct {
	discoveryv1.EndpointSliceInterface
}

func isServiceOwnerReference(ownerReference metav1.OwnerReference) bool {
	return ownerReference.APIVersion == "v1" && ownerReference.Kind == "Service"
}

// addEndpointSliceMeshHacks fakes that the parent service of the EndpointSlice
// has the cluster name in its name by changing the owner reference and the label
// pointing to the service name. It also make sure that there is a label `mesh.cilium.io/real-service-name`
// to store the real service name before its modification.
func addEndpointSliceMeshHacks(endpointSlice *discovery.EndpointSlice) {
	if endpointSlice == nil ||
		endpointSlice.Labels == nil ||
		endpointSlice.Labels[discovery.LabelManagedBy] != utils.EndpointSliceMeshControllerName {
		return
	}

	endpointSlice.Labels[meshRealServiceNameLabel] = endpointSlice.Labels[discovery.LabelServiceName]
	endpointSlice.Labels[discovery.LabelServiceName] = endpointSlice.Labels[meshRealServiceNameLabel] + "-" + endpointSlice.Labels[mcsapiv1alpha1.LabelSourceCluster]

	for i, ownerReference := range endpointSlice.OwnerReferences {
		if !isServiceOwnerReference(ownerReference) || ownerReference.Name != endpointSlice.Labels[meshRealServiceNameLabel] {
			continue
		}

		endpointSlice.OwnerReferences[i].Name = endpointSlice.Labels[discovery.LabelServiceName]
	}
}

// removeEndpointSliceMeshHacks revert the change to the parent service made in
// addEndpointSliceMeshHacks.
func removeEndpointSliceMeshHacks(endpointSlice *discovery.EndpointSlice) {
	if endpointSlice == nil ||
		endpointSlice.Labels == nil ||
		endpointSlice.Labels[discovery.LabelManagedBy] != utils.EndpointSliceMeshControllerName {
		return
	}

	for i, ownerReference := range endpointSlice.OwnerReferences {
		if !isServiceOwnerReference(ownerReference) || ownerReference.Name != endpointSlice.Labels[discovery.LabelServiceName] {
			continue
		}

		endpointSlice.OwnerReferences[i].Name = endpointSlice.Labels[meshRealServiceNameLabel]
	}

	endpointSlice.Labels[discovery.LabelServiceName] = endpointSlice.Labels[meshRealServiceNameLabel]
	delete(endpointSlice.Labels, meshRealServiceNameLabel)
}

func (c meshClientEndpointSlice) Create(ctx context.Context, endpointSlice *discovery.EndpointSlice, opts metav1.CreateOptions) (*discovery.EndpointSlice, error) {
	// Remove the epslice mesh hacks before reaching the api server
	// and add it back for the controller afterwards.
	removeEndpointSliceMeshHacks(endpointSlice)
	endpointSlice, err := c.EndpointSliceInterface.Create(ctx, endpointSlice, opts)
	addEndpointSliceMeshHacks(endpointSlice)
	return endpointSlice, err
}
func (c meshClientEndpointSlice) Update(ctx context.Context, endpointSlice *discovery.EndpointSlice, opts metav1.UpdateOptions) (*discovery.EndpointSlice, error) {
	// Remove the epslice mesh hacks before reaching the api server
	// and add it back for the controller afterwards.
	removeEndpointSliceMeshHacks(endpointSlice)
	endpointSlice, err := c.EndpointSliceInterface.Update(ctx, endpointSlice, opts)
	addEndpointSliceMeshHacks(endpointSlice)
	return endpointSlice, err
}
func (c meshClientEndpointSlice) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.EndpointSliceInterface.Delete(ctx, name, opts)
}

func (c meshClientEndpointSlice) List(ctx context.Context, opts metav1.ListOptions) (*discovery.EndpointSliceList, error) {
	list, err := c.EndpointSliceInterface.List(ctx, opts)
	if err != nil || list == nil {
		return list, err
	}

	for _, item := range list.Items {
		addEndpointSliceMeshHacks(&item)
	}
	return list, err
}
func (c meshClientEndpointSlice) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	watchInterface, err := c.EndpointSliceInterface.Watch(ctx, opts)
	return NewMeshEndpointSliceWatcher(watchInterface), err
}

// Pretty much a copy of watch.Streamwatcher but simplified to have another Streamwatcher
// as a backend while calling addEndpointSliceMeshHacks
type meshEndpointSliceWatcher struct {
	lock.Mutex
	backend watch.Interface
	result  chan watch.Event
}

func NewMeshEndpointSliceWatcher(backend watch.Interface) *meshEndpointSliceWatcher {
	sw := &meshEndpointSliceWatcher{
		backend: backend,
		result:  make(chan watch.Event),
	}

	go sw.receive()
	return sw
}

func (sw *meshEndpointSliceWatcher) ResultChan() <-chan watch.Event {
	return sw.result
}

func (sw *meshEndpointSliceWatcher) Stop() {
	sw.backend.Stop()
}

func (sw *meshEndpointSliceWatcher) receive() {
	defer utilruntime.HandleCrash()
	defer close(sw.result)

	for event := range sw.backend.ResultChan() {
		if event.Object != nil {
			if endpointSlice, ok := event.Object.(*discovery.EndpointSlice); ok {
				addEndpointSliceMeshHacks(endpointSlice)
			}
		}
		sw.result <- event
	}
}
