// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	operatorOption "github.com/cilium/cilium/operator/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
)

var (
	// PodStore has a minimal copy of all pods running in the cluster.
	// Warning: The pods stored in the cache are not intended to be used for Update
	// operations in k8s as some of its fields are not populated.
	PodStore cache.Store

	// UnmanagedPodStore has a minimal copy of the unmanaged pods running
	// in the cluster.
	// Warning: The pods stored in the cache are not intended to be used for Update
	// operations in k8s as some of its fields are not populated.
	UnmanagedPodStore cache.Store
)

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
		TransformToUnmanagedPod,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		unmanagedPodInformer.Run(ctx.Done())
	}()

	cache.WaitForCacheSync(ctx.Done(), unmanagedPodInformer.HasSynced)
}

func TransformToUnmanagedPod(obj interface{}) (interface{}, error) {
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
		return p, nil
	case cache.DeletedFinalStateUnknown:
		pod, ok := concreteObj.Obj.(*slim_corev1.Pod)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
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
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}
