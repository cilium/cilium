// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	operatorOption "github.com/cilium/cilium/operator/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
)

const PodNodeNameIndex = "pod-node"

var (
	// PodStore has a minimal copy of all pods running in the cluster.
	// Warning: The pods stored in the cache are not intended to be used for Update
	// operations in k8s as some of its fields are not populated.
	PodStore cache.Store

	// PodStoreSynced is closed once the PodStore is synced with k8s.
	PodStoreSynced = make(chan struct{})

	// UnmanagedPodStore has a minimal copy of the unmanaged pods running
	// in the cluster.
	// Warning: The pods stored in the cache are not intended to be used for Update
	// operations in k8s as some of its fields are not populated.
	UnmanagedPodStore cache.Store

	// UnmanagedPodStoreSynced is closed once the UnmanagedKubeDNSPodStore is synced
	// with k8s.
	UnmanagedPodStoreSynced = make(chan struct{})
)

// podNodeNameIndexFunc indexes pods by node name
func podNodeNameIndexFunc(obj interface{}) ([]string, error) {
	pod := obj.(*slim_corev1.Pod)
	if pod.Spec.NodeName != "" {
		return []string{pod.Spec.NodeName}, nil
	}
	return []string{}, nil
}

func PodsInit(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
	var podInformer cache.Controller
	PodStore = cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{
		PodNodeNameIndex: podNodeNameIndexFunc,
	})
	podInformer = informer.NewInformerWithStore(
		k8sUtils.ListerWatcherWithFields(
			k8sUtils.ListerWatcherFromTyped[*slim_corev1.PodList](clientset.Slim().CoreV1().Pods("")),
			fields.Everything()),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{},
		convertToPod,
		PodStore,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		podInformer.Run(ctx.Done())
	}()

	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
}

// convertToPod stores a minimal version of the pod as it is only intended
// for it to check if a pod is running in the cluster or not. The stored pod
// should not be used to update an existing pod in the kubernetes cluster.
func convertToPod(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Pod:
		p := &slim_corev1.Pod{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.Name,
				Namespace:       concreteObj.Namespace,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: slim_corev1.PodSpec{
				NodeName: concreteObj.Spec.NodeName,
			},
			Status: slim_corev1.PodStatus{
				Phase: concreteObj.Status.Phase,
			},
		}
		*concreteObj = slim_corev1.Pod{}
		return p
	case cache.DeletedFinalStateUnknown:
		pod, ok := concreteObj.Obj.(*slim_corev1.Pod)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Pod{
				TypeMeta: pod.TypeMeta,
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            pod.Name,
					Namespace:       pod.Namespace,
					ResourceVersion: pod.ResourceVersion,
				},
				Spec: slim_corev1.PodSpec{
					NodeName: pod.Spec.NodeName,
				},
				Status: slim_corev1.PodStatus{
					Phase: pod.Status.Phase,
				},
			},
		}
		// Small GC optimization
		*pod = slim_corev1.Pod{}
		return dfsu
	default:
		return obj
	}
}

func UnmanagedPodsInit(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
	var unmanagedPodInformer cache.Controller
	UnmanagedPodStore, unmanagedPodInformer = informer.NewInformer(
		k8sUtils.ListerWatcherWithModifier(
			k8sUtils.ListerWatcherFromTyped[*slim_corev1.PodList](clientset.Slim().CoreV1().Pods("")),
			func(options *metav1.ListOptions) {
				options.FieldSelector = "status.phase=Running"
				options.LabelSelector = operatorOption.Config.PodRestartSelector
			}),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{},
		convertToUnmanagedPod,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		unmanagedPodInformer.Run(ctx.Done())
	}()

	cache.WaitForCacheSync(ctx.Done(), unmanagedPodInformer.HasSynced)
}

func convertToUnmanagedPod(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Pod:
		p := &slim_corev1.Pod{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.Name,
				Namespace:       concreteObj.Namespace,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: slim_corev1.PodSpec{
				HostNetwork: concreteObj.Spec.HostNetwork,
			},
			Status: slim_corev1.PodStatus{
				StartTime: concreteObj.Status.StartTime,
			},
		}
		*concreteObj = slim_corev1.Pod{}
		return p
	case cache.DeletedFinalStateUnknown:
		pod, ok := concreteObj.Obj.(*slim_corev1.Pod)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Pod{
				TypeMeta: pod.TypeMeta,
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            pod.Name,
					Namespace:       pod.Namespace,
					ResourceVersion: pod.ResourceVersion,
				},
				Spec: slim_corev1.PodSpec{
					HostNetwork: pod.Spec.HostNetwork,
				},
				Status: slim_corev1.PodStatus{
					StartTime: pod.Status.StartTime,
				},
			},
		}
		// Small GC optimization
		*pod = slim_corev1.Pod{}
		return dfsu
	default:
		return obj
	}
}
