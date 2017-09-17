/*
Copyright 2016 The Kubernetes Authors.

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

package e2e_node

import (
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/kubernetes/test/e2e/framework"

	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = framework.KubeDescribe("Kubelet Volume Manager", func() {
	f := framework.NewDefaultFramework("kubelet-volume-manager")
	Describe("Volume Manager", func() {
		Context("On terminatation of pod with memory backed volume", func() {
			It("should remove the volume from the node", func() {
				var (
					memoryBackedPod *v1.Pod
					volumeName      string
				)
				By("Creating a pod with a memory backed volume that exits success without restart", func() {
					volumeName = "memory-volume"
					memoryBackedPod = f.PodClient().Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "pod" + string(uuid.NewUUID()),
							Namespace: f.Namespace.Name,
						},
						Spec: v1.PodSpec{
							RestartPolicy: v1.RestartPolicyNever,
							Containers: []v1.Container{
								{
									Image:   busyboxImage,
									Name:    "container" + string(uuid.NewUUID()),
									Command: []string{"sh", "-c", "echo"},
									VolumeMounts: []v1.VolumeMount{
										{
											Name:      volumeName,
											MountPath: "/tmp",
										},
									},
								},
							},
							Volumes: []v1.Volume{
								{
									Name: volumeName,
									VolumeSource: v1.VolumeSource{
										EmptyDir: &v1.EmptyDirVolumeSource{Medium: v1.StorageMediumMemory},
									},
								},
							},
						},
					})
					err := framework.WaitForPodSuccessInNamespace(f.ClientSet, memoryBackedPod.Name, f.Namespace.Name)
					Expect(err).NotTo(HaveOccurred())
				})
				By("Verifying the memory backed volume was removed from node", func() {
					volumePath := fmt.Sprintf("/tmp/%s/volumes/kubernetes.io~empty-dir/%s", string(memoryBackedPod.UID), volumeName)
					var err error
					for i := 0; i < 10; i++ {
						// need to create a new verification pod on each pass since updates
						//to the HostPath volume aren't propogated to the pod
						pod := f.PodClient().Create(&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "pod" + string(uuid.NewUUID()),
								Namespace: f.Namespace.Name,
							},
							Spec: v1.PodSpec{
								RestartPolicy: v1.RestartPolicyNever,
								Containers: []v1.Container{
									{
										Image:   busyboxImage,
										Name:    "container" + string(uuid.NewUUID()),
										Command: []string{"sh", "-c", "if [ -d " + volumePath + " ]; then exit 1; fi;"},
										VolumeMounts: []v1.VolumeMount{
											{
												Name:      "kubelet-pods",
												MountPath: "/tmp",
											},
										},
									},
								},
								Volumes: []v1.Volume{
									{
										Name: "kubelet-pods",
										VolumeSource: v1.VolumeSource{
											// TODO: remove hardcoded kubelet volume directory path
											// framework.TestContext.KubeVolumeDir is currently not populated for node e2e
											HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/kubelet/pods"},
										},
									},
								},
							},
						})
						err = framework.WaitForPodSuccessInNamespace(f.ClientSet, pod.Name, f.Namespace.Name)
						gp := int64(1)
						f.PodClient().Delete(pod.Name, &metav1.DeleteOptions{GracePeriodSeconds: &gp})
						if err == nil {
							break
						}
						<-time.After(10 * time.Second)
					}
					Expect(err).NotTo(HaveOccurred())
				})
			})
		})
	})
})
