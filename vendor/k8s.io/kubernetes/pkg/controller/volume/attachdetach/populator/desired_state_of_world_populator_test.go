/*
Copyright 2017 The Kubernetes Authors.

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

package populator

import (
	"testing"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/cache"
	volumetesting "k8s.io/kubernetes/pkg/volume/testing"
	"k8s.io/kubernetes/pkg/volume/util/volumehelper"
)

func TestFindAndAddActivePods_FindAndRemoveDeletedPods(t *testing.T) {
	fakeVolumePluginMgr, _ := volumetesting.GetTestVolumePluginMgr(t)
	fakeClient := &fake.Clientset{}

	fakeInformerFactory := informers.NewSharedInformerFactory(fakeClient, controller.NoResyncPeriodFunc())
	fakePodInformer := fakeInformerFactory.Core().V1().Pods()

	fakesDSW := cache.NewDesiredStateOfWorld(fakeVolumePluginMgr)

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dswp-test-pod",
			UID:       "dswp-test-pod-uid",
			Namespace: "dswp-test",
		},
		Spec: v1.PodSpec{
			NodeName: "dswp-test-host",
			Volumes: []v1.Volume{
				{
					Name: "dswp-test-volume-name",
					VolumeSource: v1.VolumeSource{
						GCEPersistentDisk: &v1.GCEPersistentDiskVolumeSource{
							PDName: "dswp-test-fake-device",
						},
					},
				},
			},
		},
		Status: v1.PodStatus{
			Phase: v1.PodPhase("Running"),
		},
	}

	fakePodInformer.Informer().GetStore().Add(pod)

	podName := volumehelper.GetUniquePodName(pod)

	generatedVolumeName := "fake-plugin/" + pod.Spec.Volumes[0].Name

	pvcLister := fakeInformerFactory.Core().V1().PersistentVolumeClaims().Lister()
	pvLister := fakeInformerFactory.Core().V1().PersistentVolumes().Lister()

	dswp := &desiredStateOfWorldPopulator{
		loopSleepDuration:     100 * time.Millisecond,
		listPodsRetryDuration: 3 * time.Second,
		desiredStateOfWorld:   fakesDSW,
		volumePluginMgr:       fakeVolumePluginMgr,
		podLister:             fakePodInformer.Lister(),
		pvcLister:             pvcLister,
		pvLister:              pvLister,
	}

	//add the given node to the list of nodes managed by dsw
	dswp.desiredStateOfWorld.AddNode(k8stypes.NodeName(pod.Spec.NodeName), false /*keepTerminatedPodVolumes*/)

	dswp.findAndAddActivePods()

	expectedVolumeName := v1.UniqueVolumeName(generatedVolumeName)

	//check if the given volume referenced by the pod is added to dsw
	volumeExists := dswp.desiredStateOfWorld.VolumeExists(expectedVolumeName, k8stypes.NodeName(pod.Spec.NodeName))
	if !volumeExists {
		t.Fatalf(
			"VolumeExists(%q) failed. Expected: <true> Actual: <%v>",
			expectedVolumeName,
			volumeExists)
	}

	//delete the pod and volume manually
	dswp.desiredStateOfWorld.DeletePod(podName, expectedVolumeName, k8stypes.NodeName(pod.Spec.NodeName))

	//check if the given volume referenced by the pod still exists in dsw
	volumeExists = dswp.desiredStateOfWorld.VolumeExists(expectedVolumeName, k8stypes.NodeName(pod.Spec.NodeName))
	if volumeExists {
		t.Fatalf(
			"VolumeExists(%q) failed. Expected: <false> Actual: <%v>",
			expectedVolumeName,
			volumeExists)
	}

	//add pod and volume again
	dswp.findAndAddActivePods()

	//check if the given volume referenced by the pod is added to dsw for the second time
	volumeExists = dswp.desiredStateOfWorld.VolumeExists(expectedVolumeName, k8stypes.NodeName(pod.Spec.NodeName))
	if !volumeExists {
		t.Fatalf(
			"VolumeExists(%q) failed. Expected: <true> Actual: <%v>",
			expectedVolumeName,
			volumeExists)
	}

	fakePodInformer.Informer().GetStore().Delete(pod)
	dswp.findAndRemoveDeletedPods()
	//check if the given volume referenced by the pod still exists in dsw
	volumeExists = dswp.desiredStateOfWorld.VolumeExists(expectedVolumeName, k8stypes.NodeName(pod.Spec.NodeName))
	if volumeExists {
		t.Fatalf(
			"VolumeExists(%q) failed. Expected: <false> Actual: <%v>",
			expectedVolumeName,
			volumeExists)
	}

}
