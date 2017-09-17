/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package algorithm

import (
	apps "k8s.io/api/apps/v1beta1"
	"k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	schedulerapi "k8s.io/kubernetes/plugin/pkg/scheduler/api"
	"k8s.io/kubernetes/plugin/pkg/scheduler/schedulercache"
)

// FitPredicate is a function that indicates if a pod fits into an existing node.
// The failure information is given by the error.
// TODO: Change interface{} to a specific type.
type FitPredicate func(pod *v1.Pod, meta interface{}, nodeInfo *schedulercache.NodeInfo) (bool, []PredicateFailureReason, error)

// PriorityMapFunction is a function that computes per-node results for a given node.
// TODO: Figure out the exact API of this method.
// TODO: Change interface{} to a specific type.
type PriorityMapFunction func(pod *v1.Pod, meta interface{}, nodeInfo *schedulercache.NodeInfo) (schedulerapi.HostPriority, error)

// PriorityReduceFunction is a function that aggregated per-node results and computes
// final scores for all nodes.
// TODO: Figure out the exact API of this method.
// TODO: Change interface{} to a specific type.
type PriorityReduceFunction func(pod *v1.Pod, meta interface{}, nodeNameToInfo map[string]*schedulercache.NodeInfo, result schedulerapi.HostPriorityList) error

// MetadataProducer is a function that computes metadata for a given pod.
type MetadataProducer func(pod *v1.Pod, nodeNameToInfo map[string]*schedulercache.NodeInfo) interface{}

// DEPRECATED
// Use Map-Reduce pattern for priority functions.
type PriorityFunction func(pod *v1.Pod, nodeNameToInfo map[string]*schedulercache.NodeInfo, nodes []*v1.Node) (schedulerapi.HostPriorityList, error)

type PriorityConfig struct {
	Map    PriorityMapFunction
	Reduce PriorityReduceFunction
	// TODO: Remove it after migrating all functions to
	// Map-Reduce pattern.
	Function PriorityFunction
	Weight   int
}

// EmptyMetadataProducer returns a no-op MetadataProducer type.
func EmptyMetadataProducer(pod *v1.Pod, nodeNameToInfo map[string]*schedulercache.NodeInfo) interface{} {
	return nil
}

type PredicateFailureReason interface {
	GetReason() string
}

type GetEquivalencePodFunc func(pod *v1.Pod) interface{}

// NodeLister interface represents anything that can list nodes for a scheduler.
type NodeLister interface {
	// We explicitly return []*v1.Node, instead of v1.NodeList, to avoid
	// performing expensive copies that are unneeded.
	List() ([]*v1.Node, error)
}

// PodLister interface represents anything that can list pods for a scheduler.
type PodLister interface {
	// We explicitly return []*v1.Pod, instead of v1.PodList, to avoid
	// performing expensive copies that are unneeded.
	List(labels.Selector) ([]*v1.Pod, error)
	// This is similar to "List()", but the returned slice does not
	// contain pods that don't pass `podFilter`.
	FilteredList(podFilter schedulercache.PodFilter, selector labels.Selector) ([]*v1.Pod, error)
}

// ServiceLister interface represents anything that can produce a list of services; the list is consumed by a scheduler.
type ServiceLister interface {
	// Lists all the services
	List(labels.Selector) ([]*v1.Service, error)
	// Gets the services for the given pod
	GetPodServices(*v1.Pod) ([]*v1.Service, error)
}

// ControllerLister interface represents anything that can produce a list of ReplicationController; the list is consumed by a scheduler.
type ControllerLister interface {
	// Lists all the replication controllers
	List(labels.Selector) ([]*v1.ReplicationController, error)
	// Gets the services for the given pod
	GetPodControllers(*v1.Pod) ([]*v1.ReplicationController, error)
}

// ReplicaSetLister interface represents anything that can produce a list of ReplicaSet; the list is consumed by a scheduler.
type ReplicaSetLister interface {
	// Gets the replicasets for the given pod
	GetPodReplicaSets(*v1.Pod) ([]*extensions.ReplicaSet, error)
}

var _ ControllerLister = &EmptyControllerLister{}

// EmptyControllerLister implements ControllerLister on []v1.ReplicationController returning empty data
type EmptyControllerLister struct{}

// List returns nil
func (f EmptyControllerLister) List(labels.Selector) ([]*v1.ReplicationController, error) {
	return nil, nil
}

// GetPodControllers returns nil
func (f EmptyControllerLister) GetPodControllers(pod *v1.Pod) (controllers []*v1.ReplicationController, err error) {
	return nil, nil
}

var _ ReplicaSetLister = &EmptyReplicaSetLister{}

// EmptyReplicaSetLister implements ReplicaSetLister on []extensions.ReplicaSet returning empty data
type EmptyReplicaSetLister struct{}

// GetPodReplicaSets returns nil
func (f EmptyReplicaSetLister) GetPodReplicaSets(pod *v1.Pod) (rss []*extensions.ReplicaSet, err error) {
	return nil, nil
}

// StatefulSetLister interface represents anything that can produce a list of StatefulSet; the list is consumed by a scheduler.
type StatefulSetLister interface {
	// Gets the StatefulSet for the given pod.
	GetPodStatefulSets(*v1.Pod) ([]*apps.StatefulSet, error)
}

var _ StatefulSetLister = &EmptyStatefulSetLister{}

// EmptyStatefulSetLister implements StatefulSetLister on []apps.StatefulSet returning empty data.
type EmptyStatefulSetLister struct{}

// GetPodStatefulSets of EmptyStatefulSetLister returns nil.
func (f EmptyStatefulSetLister) GetPodStatefulSets(pod *v1.Pod) (sss []*apps.StatefulSet, err error) {
	return nil, nil
}
