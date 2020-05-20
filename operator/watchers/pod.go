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
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	// PodStore has a minimal copy of all pods running in the cluster.
	// Warning: The pods stored in the cache are not intended to be used for Update
	// operations in k8s as some of its fields were are not populated.
	PodStore cache.Store

	// PodStoreSynced is closed once the PodStore is synced with k8s.
	PodStoreSynced = make(chan struct{})
)

func PodsInit(k8sClient kubernetes.Interface) {
	var podInformer cache.Controller
	PodStore, podInformer = informer.NewInformer(
		cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"pods", v1.NamespaceAll, fields.Everything()),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{},
		convertToPod,
	)
	go podInformer.Run(wait.NeverStop)

	cache.WaitForCacheSync(wait.NeverStop, podInformer.HasSynced)
	close(PodStoreSynced)
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
			},
		}
		// Small GC optimization
		*pod = slim_corev1.Pod{}
		return dfsu
	default:
		return obj
	}
}
