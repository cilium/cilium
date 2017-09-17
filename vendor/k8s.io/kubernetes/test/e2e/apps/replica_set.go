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

package apps

import (
	"fmt"
	"time"

	"k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/pkg/controller/replicaset"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

func newRS(rsName string, replicas int32, rsPodLabels map[string]string, imageName string, image string) *extensions.ReplicaSet {
	zero := int64(0)
	return &extensions.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: rsName,
		},
		Spec: extensions.ReplicaSetSpec{
			Replicas: &replicas,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: rsPodLabels,
				},
				Spec: v1.PodSpec{
					TerminationGracePeriodSeconds: &zero,
					Containers: []v1.Container{
						{
							Name:  imageName,
							Image: image,
						},
					},
				},
			},
		},
	}
}

func newPodQuota(name, number string) *v1.ResourceQuota {
	return &v1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				v1.ResourcePods: resource.MustParse(number),
			},
		},
	}
}

var _ = SIGDescribe("ReplicaSet", func() {
	f := framework.NewDefaultFramework("replicaset")

	It("should serve a basic image on each replica with a public image [Conformance]", func() {
		testReplicaSetServeImageOrFail(f, "basic", framework.ServeHostnameImage)
	})

	It("should serve a basic image on each replica with a private image", func() {
		// requires private images
		framework.SkipUnlessProviderIs("gce", "gke")
		privateimage := imageutils.ServeHostname
		privateimage.SetRegistry(imageutils.PrivateRegistry)
		testReplicaSetServeImageOrFail(f, "private", imageutils.GetE2EImage(privateimage))
	})

	It("should surface a failure condition on a common issue like exceeded quota", func() {
		testReplicaSetConditionCheck(f)
	})

	It("should adopt matching pods on creation", func() {
		testRSAdoptMatchingOrphans(f)
	})

	It("should release no longer matching pods", func() {
		testRSReleaseControlledNotMatching(f)
	})
})

// A basic test to check the deployment of an image using a ReplicaSet. The
// image serves its hostname which is checked for each replica.
func testReplicaSetServeImageOrFail(f *framework.Framework, test string, image string) {
	name := "my-hostname-" + test + "-" + string(uuid.NewUUID())
	replicas := int32(1)

	// Create a ReplicaSet for a service that serves its hostname.
	// The source for the Docker containter kubernetes/serve_hostname is
	// in contrib/for-demos/serve_hostname
	framework.Logf("Creating ReplicaSet %s", name)
	newRS := newRS(name, replicas, map[string]string{"name": name}, name, image)
	newRS.Spec.Template.Spec.Containers[0].Ports = []v1.ContainerPort{{ContainerPort: 9376}}
	_, err := f.ClientSet.Extensions().ReplicaSets(f.Namespace.Name).Create(newRS)
	Expect(err).NotTo(HaveOccurred())

	// Check that pods for the new RS were created.
	// TODO: Maybe switch PodsCreated to just check owner references.
	pods, err := framework.PodsCreated(f.ClientSet, f.Namespace.Name, name, replicas)
	Expect(err).NotTo(HaveOccurred())

	// Wait for the pods to enter the running state. Waiting loops until the pods
	// are running so non-running pods cause a timeout for this test.
	framework.Logf("Ensuring a pod for ReplicaSet %q is running", name)
	running := int32(0)
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp != nil {
			continue
		}
		err = f.WaitForPodRunning(pod.Name)
		if err != nil {
			updatePod, getErr := f.ClientSet.Core().Pods(f.Namespace.Name).Get(pod.Name, metav1.GetOptions{})
			if getErr == nil {
				err = fmt.Errorf("Pod %q never run (phase: %s, conditions: %+v): %v", updatePod.Name, updatePod.Status.Phase, updatePod.Status.Conditions, err)
			} else {
				err = fmt.Errorf("Pod %q never run: %v", pod.Name, err)
			}
		}
		Expect(err).NotTo(HaveOccurred())
		framework.Logf("Pod %q is running (conditions: %+v)", pod.Name, pod.Status.Conditions)
		running++
	}

	// Sanity check
	if running != replicas {
		Expect(fmt.Errorf("unexpected number of running pods: %+v", pods.Items)).NotTo(HaveOccurred())
	}

	// Verify that something is listening.
	framework.Logf("Trying to dial the pod")
	retryTimeout := 2 * time.Minute
	retryInterval := 5 * time.Second
	label := labels.SelectorFromSet(labels.Set(map[string]string{"name": name}))
	err = wait.Poll(retryInterval, retryTimeout, framework.PodProxyResponseChecker(f.ClientSet, f.Namespace.Name, label, name, true, pods).CheckAllResponses)
	if err != nil {
		framework.Failf("Did not get expected responses within the timeout period of %.2f seconds.", retryTimeout.Seconds())
	}
}

// 1. Create a quota restricting pods in the current namespace to 2.
// 2. Create a replica set that wants to run 3 pods.
// 3. Check replica set conditions for a ReplicaFailure condition.
// 4. Scale down the replica set and observe the condition is gone.
func testReplicaSetConditionCheck(f *framework.Framework) {
	c := f.ClientSet
	namespace := f.Namespace.Name
	name := "condition-test"

	By(fmt.Sprintf("Creating quota %q that allows only two pods to run in the current namespace", name))
	quota := newPodQuota(name, "2")
	_, err := c.Core().ResourceQuotas(namespace).Create(quota)
	Expect(err).NotTo(HaveOccurred())

	err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		quota, err = c.Core().ResourceQuotas(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		quantity := resource.MustParse("2")
		podQuota := quota.Status.Hard[v1.ResourcePods]
		return (&podQuota).Cmp(quantity) == 0, nil
	})
	if err == wait.ErrWaitTimeout {
		err = fmt.Errorf("resource quota %q never synced", name)
	}
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Creating replica set %q that asks for more than the allowed pod quota", name))
	rs := newRS(name, 3, map[string]string{"name": name}, NginxImageName, NginxImage)
	rs, err = c.Extensions().ReplicaSets(namespace).Create(rs)
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Checking replica set %q has the desired failure condition set", name))
	generation := rs.Generation
	conditions := rs.Status.Conditions
	err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		rs, err = c.Extensions().ReplicaSets(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if generation > rs.Status.ObservedGeneration {
			return false, nil
		}
		conditions = rs.Status.Conditions

		cond := replicaset.GetCondition(rs.Status, extensions.ReplicaSetReplicaFailure)
		return cond != nil, nil

	})
	if err == wait.ErrWaitTimeout {
		err = fmt.Errorf("rs controller never added the failure condition for replica set %q: %#v", name, conditions)
	}
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Scaling down replica set %q to satisfy pod quota", name))
	rs, err = framework.UpdateReplicaSetWithRetries(c, namespace, name, func(update *extensions.ReplicaSet) {
		x := int32(2)
		update.Spec.Replicas = &x
	})
	Expect(err).NotTo(HaveOccurred())

	By(fmt.Sprintf("Checking replica set %q has no failure condition set", name))
	generation = rs.Generation
	conditions = rs.Status.Conditions
	err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		rs, err = c.Extensions().ReplicaSets(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if generation > rs.Status.ObservedGeneration {
			return false, nil
		}
		conditions = rs.Status.Conditions

		cond := replicaset.GetCondition(rs.Status, extensions.ReplicaSetReplicaFailure)
		return cond == nil, nil
	})
	if err == wait.ErrWaitTimeout {
		err = fmt.Errorf("rs controller never removed the failure condition for rs %q: %#v", name, conditions)
	}
	Expect(err).NotTo(HaveOccurred())
}

func testRSAdoptMatchingOrphans(f *framework.Framework) {
	name := "pod-adoption"
	By(fmt.Sprintf("Given a Pod with a 'name' label %s is created", name))
	p := f.PodClient().CreateSync(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"name": name,
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  name,
					Image: NginxImageName,
				},
			},
		},
	})

	By("When a replicaset with a matching selector is created")
	replicas := int32(1)
	rsSt := newRS(name, replicas, map[string]string{"name": name}, name, NginxImageName)
	rsSt.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"name": name}}
	rs, err := f.ClientSet.Extensions().ReplicaSets(f.Namespace.Name).Create(rsSt)
	Expect(err).NotTo(HaveOccurred())

	By("Then the orphan pod is adopted")
	err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		p2, err := f.ClientSet.Core().Pods(f.Namespace.Name).Get(p.Name, metav1.GetOptions{})
		// The Pod p should either be adopted or deleted by the ReplicaSet
		if errors.IsNotFound(err) {
			return true, nil
		}
		Expect(err).NotTo(HaveOccurred())
		for _, owner := range p2.OwnerReferences {
			if *owner.Controller && owner.UID == rs.UID {
				// pod adopted
				return true, nil
			}
		}
		// pod still not adopted
		return false, nil
	})
	Expect(err).NotTo(HaveOccurred())
}

func testRSReleaseControlledNotMatching(f *framework.Framework) {
	name := "pod-release"
	By("Given a ReplicaSet is created")
	replicas := int32(1)
	rsSt := newRS(name, replicas, map[string]string{"name": name}, name, NginxImageName)
	rsSt.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"name": name}}
	rs, err := f.ClientSet.Extensions().ReplicaSets(f.Namespace.Name).Create(rsSt)
	Expect(err).NotTo(HaveOccurred())

	By("When the matched label of one of its pods change")
	pods, err := framework.PodsCreated(f.ClientSet, f.Namespace.Name, rs.Name, replicas)
	Expect(err).NotTo(HaveOccurred())

	p := pods.Items[0]
	err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		pod, err := f.ClientSet.Core().Pods(f.Namespace.Name).Get(p.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		pod.Labels = map[string]string{"name": "not-matching-name"}
		_, err = f.ClientSet.Core().Pods(f.Namespace.Name).Update(pod)
		if err != nil && errors.IsConflict(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
	Expect(err).NotTo(HaveOccurred())

	By("Then the pod is released")
	err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		p2, err := f.ClientSet.Core().Pods(f.Namespace.Name).Get(p.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		for _, owner := range p2.OwnerReferences {
			if *owner.Controller && owner.UID == rs.UID {
				// pod still belonging to the replicaset
				return false, nil
			}
		}
		// pod already released
		return true, nil
	})
	Expect(err).NotTo(HaveOccurred())
}
