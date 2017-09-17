/*
Copyright 2015 The Kubernetes Authors.

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

package garbagecollector

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionstestserver "k8s.io/apiextensions-apiserver/test/integration/testserver"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/discovery"
	cacheddiscovery "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	apitesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/pkg/controller/garbagecollector"
	"k8s.io/kubernetes/test/integration"

	"github.com/coreos/pkg/capnslog"
)

func getForegroundOptions() *metav1.DeleteOptions {
	policy := metav1.DeletePropagationForeground
	return &metav1.DeleteOptions{PropagationPolicy: &policy}
}

func getOrphanOptions() *metav1.DeleteOptions {
	var trueVar = true
	return &metav1.DeleteOptions{OrphanDependents: &trueVar}
}

func getNonOrphanOptions() *metav1.DeleteOptions {
	var falseVar = false
	return &metav1.DeleteOptions{OrphanDependents: &falseVar}
}

const garbageCollectedPodName = "test.pod.1"
const independentPodName = "test.pod.2"
const oneValidOwnerPodName = "test.pod.3"
const toBeDeletedRCName = "test.rc.1"
const remainingRCName = "test.rc.2"

func newPod(podName, podNamespace string, ownerReferences []metav1.OwnerReference) *v1.Pod {
	for i := 0; i < len(ownerReferences); i++ {
		if len(ownerReferences[i].Kind) == 0 {
			ownerReferences[i].Kind = "ReplicationController"
		}
		ownerReferences[i].APIVersion = "v1"
	}
	return &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            podName,
			Namespace:       podNamespace,
			OwnerReferences: ownerReferences,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "fake-name",
					Image: "fakeimage",
				},
			},
		},
	}
}

func newOwnerRC(name, namespace string) *v1.ReplicationController {
	return &v1.ReplicationController{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ReplicationController",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: v1.ReplicationControllerSpec{
			Selector: map[string]string{"name": "test"},
			Template: &v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"name": "test"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "fake-name",
							Image: "fakeimage",
						},
					},
				},
			},
		},
	}
}

func newCRDInstance(definition *apiextensionsv1beta1.CustomResourceDefinition, namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"kind":       definition.Spec.Names.Kind,
			"apiVersion": definition.Spec.Group + "/" + definition.Spec.Version,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
		},
	}
}

func newConfigMap(namespace, name string) *v1.ConfigMap {
	return &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
}

func link(t *testing.T, owner, dependent metav1.Object) {
	ownerType, err := meta.TypeAccessor(owner)
	if err != nil {
		t.Fatalf("failed to get type info for %#v: %v", owner, err)
	}
	ref := metav1.OwnerReference{
		Kind:       ownerType.GetKind(),
		APIVersion: ownerType.GetAPIVersion(),
		Name:       owner.GetName(),
		UID:        owner.GetUID(),
	}
	dependent.SetOwnerReferences(append(dependent.GetOwnerReferences(), ref))
}

func createRandomCustomResourceDefinition(
	t *testing.T, apiExtensionClient apiextensionsclientset.Interface,
	clientPool dynamic.ClientPool,
	namespace string,
) (*apiextensionsv1beta1.CustomResourceDefinition, dynamic.ResourceInterface) {
	// Create a random custom resource definition and ensure it's available for
	// use.
	definition := apiextensionstestserver.NewRandomNameCustomResourceDefinition(apiextensionsv1beta1.NamespaceScoped)

	client, err := apiextensionstestserver.CreateNewCustomResourceDefinition(definition, apiExtensionClient, clientPool)
	if err != nil {
		t.Fatalf("failed to create CustomResourceDefinition: %v", err)
	}

	// Get a client for the custom resource.
	resourceClient := client.Resource(&metav1.APIResource{
		Name:       definition.Spec.Names.Plural,
		Namespaced: true,
	}, namespace)
	return definition, resourceClient
}

type testContext struct {
	tearDown           func()
	gc                 *garbagecollector.GarbageCollector
	clientSet          clientset.Interface
	apiExtensionClient apiextensionsclientset.Interface
	clientPool         dynamic.ClientPool
	startGC            func(workers int)
	// syncPeriod is how often the GC started with startGC will be resynced.
	syncPeriod time.Duration
}

// if workerCount > 0, will start the GC, otherwise it's up to the caller to Run() the GC.
func setup(t *testing.T, workerCount int) *testContext {
	masterConfig, tearDownMaster := apitesting.StartTestServerOrDie(t)

	// TODO: Disable logging here until we resolve teardown issues which result in
	// massive log spam. Another path forward would be to refactor
	// StartTestServerOrDie to work with the etcd instance already started by the
	// integration test scripts.
	// See https://github.com/kubernetes/kubernetes/issues/49489.
	repo, err := capnslog.GetRepoLogger("github.com/coreos/etcd")
	if err != nil {
		t.Fatalf("couldn't configure logging: %v", err)
	}
	repo.SetLogLevel(map[string]capnslog.LogLevel{
		"etcdserver/api/v3rpc": capnslog.CRITICAL,
	})

	clientSet, err := clientset.NewForConfig(masterConfig)
	if err != nil {
		t.Fatalf("error creating clientset: %v", err)
	}

	// Helpful stuff for testing CRD.
	apiExtensionClient, err := apiextensionsclientset.NewForConfig(masterConfig)
	if err != nil {
		t.Fatalf("error creating extension clientset: %v", err)
	}
	// CreateNewCustomResourceDefinition wants to use this namespace for verifying
	// namespace-scoped CRD creation.
	createNamespaceOrDie("aval", clientSet, t)

	discoveryClient := cacheddiscovery.NewMemCacheClient(clientSet.Discovery())
	restMapper := discovery.NewDeferredDiscoveryRESTMapper(discoveryClient, meta.InterfacesForUnstructured)
	restMapper.Reset()
	deletableResources, err := garbagecollector.GetDeletableResources(discoveryClient)
	if err != nil {
		t.Fatalf("unable to get deletable resources: %v", err)
	}
	config := *masterConfig
	config.ContentConfig = dynamic.ContentConfig()
	metaOnlyClientPool := dynamic.NewClientPool(&config, restMapper, dynamic.LegacyAPIPathResolverFunc)
	clientPool := dynamic.NewClientPool(&config, restMapper, dynamic.LegacyAPIPathResolverFunc)
	sharedInformers := informers.NewSharedInformerFactory(clientSet, 0)
	alwaysStarted := make(chan struct{})
	close(alwaysStarted)
	gc, err := garbagecollector.NewGarbageCollector(
		metaOnlyClientPool,
		clientPool,
		restMapper,
		deletableResources,
		garbagecollector.DefaultIgnoredResources(),
		sharedInformers,
		alwaysStarted,
	)
	if err != nil {
		t.Fatalf("failed to create garbage collector: %v", err)
	}

	stopCh := make(chan struct{})
	tearDown := func() {
		close(stopCh)
		tearDownMaster()
		repo.SetLogLevel(map[string]capnslog.LogLevel{
			"etcdserver/api/v3rpc": capnslog.ERROR,
		})
	}
	syncPeriod := 5 * time.Second
	startGC := func(workers int) {
		go gc.Run(workers, stopCh)
		go gc.Sync(clientSet.Discovery(), syncPeriod, stopCh)
	}

	if workerCount > 0 {
		startGC(workerCount)
	}

	return &testContext{
		tearDown:           tearDown,
		gc:                 gc,
		clientSet:          clientSet,
		apiExtensionClient: apiExtensionClient,
		clientPool:         clientPool,
		startGC:            startGC,
		syncPeriod:         syncPeriod,
	}
}

func createNamespaceOrDie(name string, c clientset.Interface, t *testing.T) *v1.Namespace {
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if _, err := c.Core().Namespaces().Create(ns); err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}
	falseVar := false
	_, err := c.Core().ServiceAccounts(ns.Name).Create(&v1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: "default"},
		AutomountServiceAccountToken: &falseVar,
	})
	if err != nil {
		t.Fatalf("failed to create service account: %v", err)
	}
	return ns
}

func deleteNamespaceOrDie(name string, c clientset.Interface, t *testing.T) {
	zero := int64(0)
	background := metav1.DeletePropagationBackground
	err := c.Core().Namespaces().Delete(name, &metav1.DeleteOptions{GracePeriodSeconds: &zero, PropagationPolicy: &background})
	if err != nil {
		t.Fatalf("failed to delete namespace %q: %v", name, err)
	}
}

// This test simulates the cascading deletion.
func TestCascadingDeletion(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	gc, clientSet := ctx.gc, ctx.clientSet

	ns := createNamespaceOrDie("gc-cascading-deletion", clientSet, t)
	defer deleteNamespaceOrDie(ns.Name, clientSet, t)

	rcClient := clientSet.Core().ReplicationControllers(ns.Name)
	podClient := clientSet.Core().Pods(ns.Name)

	toBeDeletedRC, err := rcClient.Create(newOwnerRC(toBeDeletedRCName, ns.Name))
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}
	remainingRC, err := rcClient.Create(newOwnerRC(remainingRCName, ns.Name))
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}

	rcs, err := rcClient.List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list replication controllers: %v", err)
	}
	if len(rcs.Items) != 2 {
		t.Fatalf("Expect only 2 replication controller")
	}

	// this pod should be cascadingly deleted.
	pod := newPod(garbageCollectedPodName, ns.Name, []metav1.OwnerReference{{UID: toBeDeletedRC.ObjectMeta.UID, Name: toBeDeletedRCName}})
	_, err = podClient.Create(pod)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}

	// this pod shouldn't be cascadingly deleted, because it has a valid reference.
	pod = newPod(oneValidOwnerPodName, ns.Name, []metav1.OwnerReference{
		{UID: toBeDeletedRC.ObjectMeta.UID, Name: toBeDeletedRCName},
		{UID: remainingRC.ObjectMeta.UID, Name: remainingRCName},
	})
	_, err = podClient.Create(pod)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}

	// this pod shouldn't be cascadingly deleted, because it doesn't have an owner.
	pod = newPod(independentPodName, ns.Name, []metav1.OwnerReference{})
	_, err = podClient.Create(pod)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}

	// set up watch
	pods, err := podClient.List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list pods: %v", err)
	}
	if len(pods.Items) != 3 {
		t.Fatalf("Expect only 3 pods")
	}
	// delete one of the replication controller
	if err := rcClient.Delete(toBeDeletedRCName, getNonOrphanOptions()); err != nil {
		t.Fatalf("failed to delete replication controller: %v", err)
	}
	// sometimes the deletion of the RC takes long time to be observed by
	// the gc, so wait for the garbage collector to observe the deletion of
	// the toBeDeletedRC
	if err := wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
		return !gc.GraphHasUID([]types.UID{toBeDeletedRC.ObjectMeta.UID}), nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := integration.WaitForPodToDisappear(podClient, garbageCollectedPodName, 5*time.Second, 30*time.Second); err != nil {
		t.Fatalf("expect pod %s to be garbage collected, got err= %v", garbageCollectedPodName, err)
	}
	// checks the garbage collect doesn't delete pods it shouldn't delete.
	if _, err := podClient.Get(independentPodName, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := podClient.Get(oneValidOwnerPodName, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
}

// This test simulates the case where an object is created with an owner that
// doesn't exist. It verifies the GC will delete such an object.
func TestCreateWithNonExistentOwner(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	clientSet := ctx.clientSet

	ns := createNamespaceOrDie("gc-non-existing-owner", clientSet, t)
	defer deleteNamespaceOrDie(ns.Name, clientSet, t)

	podClient := clientSet.Core().Pods(ns.Name)

	pod := newPod(garbageCollectedPodName, ns.Name, []metav1.OwnerReference{{UID: "doesn't matter", Name: toBeDeletedRCName}})
	_, err := podClient.Create(pod)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}

	// set up watch
	pods, err := podClient.List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list pods: %v", err)
	}
	if len(pods.Items) > 1 {
		t.Fatalf("Unexpected pod list: %v", pods.Items)
	}
	// wait for the garbage collector to delete the pod
	if err := integration.WaitForPodToDisappear(podClient, garbageCollectedPodName, 5*time.Second, 30*time.Second); err != nil {
		t.Fatalf("expect pod %s to be garbage collected, got err= %v", garbageCollectedPodName, err)
	}
}

func setupRCsPods(t *testing.T, gc *garbagecollector.GarbageCollector, clientSet clientset.Interface, nameSuffix, namespace string, initialFinalizers []string, options *metav1.DeleteOptions, wg *sync.WaitGroup, rcUIDs chan types.UID) {
	defer wg.Done()
	rcClient := clientSet.Core().ReplicationControllers(namespace)
	podClient := clientSet.Core().Pods(namespace)
	// create rc.
	rcName := "test.rc." + nameSuffix
	rc := newOwnerRC(rcName, namespace)
	rc.ObjectMeta.Finalizers = initialFinalizers
	rc, err := rcClient.Create(rc)
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}
	rcUIDs <- rc.ObjectMeta.UID
	// create pods.
	var podUIDs []types.UID
	for j := 0; j < 3; j++ {
		podName := "test.pod." + nameSuffix + "-" + strconv.Itoa(j)
		pod := newPod(podName, namespace, []metav1.OwnerReference{{UID: rc.ObjectMeta.UID, Name: rc.ObjectMeta.Name}})
		_, err = podClient.Create(pod)
		if err != nil {
			t.Fatalf("Failed to create Pod: %v", err)
		}
		podUIDs = append(podUIDs, pod.ObjectMeta.UID)
	}
	orphan := (options != nil && options.OrphanDependents != nil && *options.OrphanDependents) || (options == nil && len(initialFinalizers) != 0 && initialFinalizers[0] == metav1.FinalizerOrphanDependents)
	// if we intend to orphan the pods, we need wait for the gc to observe the
	// creation of the pods, otherwise if the deletion of RC is observed before
	// the creation of the pods, the pods will not be orphaned.
	if orphan {
		wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) { return gc.GraphHasUID(podUIDs), nil })
	}
	// delete the rc
	if err := rcClient.Delete(rc.ObjectMeta.Name, options); err != nil {
		t.Fatalf("failed to delete replication controller: %v", err)
	}
}

func verifyRemainingObjects(t *testing.T, clientSet clientset.Interface, namespace string, rcNum, podNum int) (bool, error) {
	rcClient := clientSet.Core().ReplicationControllers(namespace)
	podClient := clientSet.Core().Pods(namespace)
	pods, err := podClient.List(metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("Failed to list pods: %v", err)
	}
	var ret = true
	if len(pods.Items) != podNum {
		ret = false
		t.Logf("expect %d pods, got %d pods", podNum, len(pods.Items))
	}
	rcs, err := rcClient.List(metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("Failed to list replication controllers: %v", err)
	}
	if len(rcs.Items) != rcNum {
		ret = false
		t.Logf("expect %d RCs, got %d RCs", rcNum, len(rcs.Items))
	}
	return ret, nil
}

// The stress test is not very stressful, because we need to control the running
// time of our pre-submit tests to increase submit-queue throughput. We'll add
// e2e tests that put more stress.
func TestStressingCascadingDeletion(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	gc, clientSet := ctx.gc, ctx.clientSet

	ns := createNamespaceOrDie("gc-stressing-cascading-deletion", clientSet, t)
	defer deleteNamespaceOrDie(ns.Name, clientSet, t)

	const collections = 10
	var wg sync.WaitGroup
	wg.Add(collections * 4)
	rcUIDs := make(chan types.UID, collections*4)
	for i := 0; i < collections; i++ {
		// rc is created with empty finalizers, deleted with nil delete options, pods will remain.
		go setupRCsPods(t, gc, clientSet, "collection1-"+strconv.Itoa(i), ns.Name, []string{}, nil, &wg, rcUIDs)
		// rc is created with the orphan finalizer, deleted with nil options, pods will remain.
		go setupRCsPods(t, gc, clientSet, "collection2-"+strconv.Itoa(i), ns.Name, []string{metav1.FinalizerOrphanDependents}, nil, &wg, rcUIDs)
		// rc is created with the orphan finalizer, deleted with DeleteOptions.OrphanDependents=false, pods will be deleted.
		go setupRCsPods(t, gc, clientSet, "collection3-"+strconv.Itoa(i), ns.Name, []string{metav1.FinalizerOrphanDependents}, getNonOrphanOptions(), &wg, rcUIDs)
		// rc is created with empty finalizers, deleted with DeleteOptions.OrphanDependents=true, pods will remain.
		go setupRCsPods(t, gc, clientSet, "collection4-"+strconv.Itoa(i), ns.Name, []string{}, getOrphanOptions(), &wg, rcUIDs)
	}
	wg.Wait()
	t.Logf("all pods are created, all replications controllers are created then deleted")
	// wait for the RCs and Pods to reach the expected numbers.
	if err := wait.Poll(5*time.Second, 300*time.Second, func() (bool, error) {
		podsInEachCollection := 3
		// see the comments on the calls to setupRCsPods for details
		remainingGroups := 3
		return verifyRemainingObjects(t, clientSet, ns.Name, 0, collections*podsInEachCollection*remainingGroups)
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("number of remaining replication controllers and pods are as expected")

	// verify the remaining pods all have "orphan" in their names.
	podClient := clientSet.Core().Pods(ns.Name)
	pods, err := podClient.List(metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, pod := range pods.Items {
		if !strings.Contains(pod.ObjectMeta.Name, "collection1-") && !strings.Contains(pod.ObjectMeta.Name, "collection2-") && !strings.Contains(pod.ObjectMeta.Name, "collection4-") {
			t.Errorf("got unexpected remaining pod: %#v", pod)
		}
	}

	// verify there is no node representing replication controllers in the gc's graph
	uids := make([]types.UID, 0, collections)
	for i := 0; i < collections; i++ {
		uid := <-rcUIDs
		uids = append(uids, uid)
	}
	if gc.GraphHasUID(uids) {
		t.Errorf("Expect all nodes representing replication controllers are removed from the Propagator's graph")
	}
}

func TestOrphaning(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	gc, clientSet := ctx.gc, ctx.clientSet

	ns := createNamespaceOrDie("gc-orphaning", clientSet, t)
	defer deleteNamespaceOrDie(ns.Name, clientSet, t)

	podClient := clientSet.Core().Pods(ns.Name)
	rcClient := clientSet.Core().ReplicationControllers(ns.Name)
	// create the RC with the orphan finalizer set
	toBeDeletedRC := newOwnerRC(toBeDeletedRCName, ns.Name)
	toBeDeletedRC, err := rcClient.Create(toBeDeletedRC)
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}

	// these pods should be orphaned.
	var podUIDs []types.UID
	podsNum := 3
	for i := 0; i < podsNum; i++ {
		podName := garbageCollectedPodName + strconv.Itoa(i)
		pod := newPod(podName, ns.Name, []metav1.OwnerReference{{UID: toBeDeletedRC.ObjectMeta.UID, Name: toBeDeletedRCName}})
		_, err = podClient.Create(pod)
		if err != nil {
			t.Fatalf("Failed to create Pod: %v", err)
		}
		podUIDs = append(podUIDs, pod.ObjectMeta.UID)
	}

	// we need wait for the gc to observe the creation of the pods, otherwise if
	// the deletion of RC is observed before the creation of the pods, the pods
	// will not be orphaned.
	wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) { return gc.GraphHasUID(podUIDs), nil })

	err = rcClient.Delete(toBeDeletedRCName, getOrphanOptions())
	if err != nil {
		t.Fatalf("Failed to gracefully delete the rc: %v", err)
	}
	// verify the toBeDeleteRC is deleted
	if err := wait.PollImmediate(5*time.Second, 30*time.Second, func() (bool, error) {
		rcs, err := rcClient.List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		if len(rcs.Items) == 0 {
			t.Logf("Still has %d RCs", len(rcs.Items))
			return true, nil
		}
		return false, nil
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// verify pods don't have the ownerPod as an owner anymore
	pods, err := podClient.List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list pods: %v", err)
	}
	if len(pods.Items) != podsNum {
		t.Errorf("Expect %d pod(s), but got %#v", podsNum, pods)
	}
	for _, pod := range pods.Items {
		if len(pod.ObjectMeta.OwnerReferences) != 0 {
			t.Errorf("pod %s still has non-empty OwnerReferences: %v", pod.ObjectMeta.Name, pod.ObjectMeta.OwnerReferences)
		}
	}
}

func TestSolidOwnerDoesNotBlockWaitingOwner(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	clientSet := ctx.clientSet

	ns := createNamespaceOrDie("gc-foreground1", clientSet, t)
	defer deleteNamespaceOrDie(ns.Name, clientSet, t)

	podClient := clientSet.Core().Pods(ns.Name)
	rcClient := clientSet.Core().ReplicationControllers(ns.Name)
	// create the RC with the orphan finalizer set
	toBeDeletedRC, err := rcClient.Create(newOwnerRC(toBeDeletedRCName, ns.Name))
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}
	remainingRC, err := rcClient.Create(newOwnerRC(remainingRCName, ns.Name))
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}
	trueVar := true
	pod := newPod("pod", ns.Name, []metav1.OwnerReference{
		{UID: toBeDeletedRC.ObjectMeta.UID, Name: toBeDeletedRC.Name, BlockOwnerDeletion: &trueVar},
		{UID: remainingRC.ObjectMeta.UID, Name: remainingRC.Name},
	})
	_, err = podClient.Create(pod)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}

	err = rcClient.Delete(toBeDeletedRCName, getForegroundOptions())
	if err != nil {
		t.Fatalf("Failed to delete the rc: %v", err)
	}
	// verify the toBeDeleteRC is deleted
	if err := wait.PollImmediate(5*time.Second, 30*time.Second, func() (bool, error) {
		_, err := rcClient.Get(toBeDeletedRC.Name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// verify pods don't have the toBeDeleteRC as an owner anymore
	pod, err = podClient.Get("pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to list pods: %v", err)
	}
	if len(pod.ObjectMeta.OwnerReferences) != 1 {
		t.Errorf("expect pod to have only one ownerReference: got %#v", pod.ObjectMeta.OwnerReferences)
	} else if pod.ObjectMeta.OwnerReferences[0].Name != remainingRC.Name {
		t.Errorf("expect pod to have an ownerReference pointing to %s, got %#v", remainingRC.Name, pod.ObjectMeta.OwnerReferences)
	}
}

func TestNonBlockingOwnerRefDoesNotBlock(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	clientSet := ctx.clientSet

	ns := createNamespaceOrDie("gc-foreground2", clientSet, t)
	defer deleteNamespaceOrDie(ns.Name, clientSet, t)

	podClient := clientSet.Core().Pods(ns.Name)
	rcClient := clientSet.Core().ReplicationControllers(ns.Name)
	// create the RC with the orphan finalizer set
	toBeDeletedRC, err := rcClient.Create(newOwnerRC(toBeDeletedRCName, ns.Name))
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}
	// BlockingOwnerDeletion is not set
	pod1 := newPod("pod1", ns.Name, []metav1.OwnerReference{
		{UID: toBeDeletedRC.ObjectMeta.UID, Name: toBeDeletedRC.Name},
	})
	// adding finalizer that no controller handles, so that the pod won't be deleted
	pod1.ObjectMeta.Finalizers = []string{"x/y"}
	// BlockingOwnerDeletion is false
	falseVar := false
	pod2 := newPod("pod2", ns.Name, []metav1.OwnerReference{
		{UID: toBeDeletedRC.ObjectMeta.UID, Name: toBeDeletedRC.Name, BlockOwnerDeletion: &falseVar},
	})
	// adding finalizer that no controller handles, so that the pod won't be deleted
	pod2.ObjectMeta.Finalizers = []string{"x/y"}
	_, err = podClient.Create(pod1)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}
	_, err = podClient.Create(pod2)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}

	err = rcClient.Delete(toBeDeletedRCName, getForegroundOptions())
	if err != nil {
		t.Fatalf("Failed to delete the rc: %v", err)
	}
	// verify the toBeDeleteRC is deleted
	if err := wait.PollImmediate(5*time.Second, 30*time.Second, func() (bool, error) {
		_, err := rcClient.Get(toBeDeletedRC.Name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// verify pods are still there
	pods, err := podClient.List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list pods: %v", err)
	}
	if len(pods.Items) != 2 {
		t.Errorf("expect there to be 2 pods, got %#v", pods.Items)
	}
}

func TestBlockingOwnerRefDoesBlock(t *testing.T) {
	ctx := setup(t, 0)
	defer ctx.tearDown()
	gc, clientSet := ctx.gc, ctx.clientSet

	ns := createNamespaceOrDie("foo", clientSet, t)
	defer deleteNamespaceOrDie(ns.Name, clientSet, t)

	podClient := clientSet.Core().Pods(ns.Name)
	rcClient := clientSet.Core().ReplicationControllers(ns.Name)
	// create the RC with the orphan finalizer set
	toBeDeletedRC, err := rcClient.Create(newOwnerRC(toBeDeletedRCName, ns.Name))
	if err != nil {
		t.Fatalf("Failed to create replication controller: %v", err)
	}
	trueVar := true
	pod := newPod("pod", ns.Name, []metav1.OwnerReference{
		{UID: toBeDeletedRC.ObjectMeta.UID, Name: toBeDeletedRC.Name, BlockOwnerDeletion: &trueVar},
	})
	// adding finalizer that no controller handles, so that the pod won't be deleted
	pod.ObjectMeta.Finalizers = []string{"x/y"}
	_, err = podClient.Create(pod)
	if err != nil {
		t.Fatalf("Failed to create Pod: %v", err)
	}

	// this makes sure the garbage collector will have added the pod to its
	// dependency graph before handling the foreground deletion of the rc.
	ctx.startGC(5)
	timeout := make(chan struct{})
	go func() {
		select {
		case <-time.After(5 * time.Second):
			close(timeout)
		}
	}()
	if !cache.WaitForCacheSync(timeout, gc.IsSynced) {
		t.Fatalf("failed to wait for garbage collector to be synced")
	}

	err = rcClient.Delete(toBeDeletedRCName, getForegroundOptions())
	if err != nil {
		t.Fatalf("Failed to delete the rc: %v", err)
	}
	time.Sleep(15 * time.Second)
	// verify the toBeDeleteRC is NOT deleted
	_, err = rcClient.Get(toBeDeletedRC.Name, metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// verify pods are still there
	pods, err := podClient.List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list pods: %v", err)
	}
	if len(pods.Items) != 1 {
		t.Errorf("expect there to be 1 pods, got %#v", pods.Items)
	}
}

// TestCustomResourceCascadingDeletion ensures the basic cascading delete
// behavior supports custom resources.
func TestCustomResourceCascadingDeletion(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	clientSet, apiExtensionClient, clientPool := ctx.clientSet, ctx.apiExtensionClient, ctx.clientPool

	ns := createNamespaceOrDie("crd-cascading", clientSet, t)

	definition, resourceClient := createRandomCustomResourceDefinition(t, apiExtensionClient, clientPool, ns.Name)

	// Create a custom owner resource.
	owner := newCRDInstance(definition, ns.Name, names.SimpleNameGenerator.GenerateName("owner"))
	owner, err := resourceClient.Create(owner)
	if err != nil {
		t.Fatalf("failed to create owner resource %q: %v", owner.GetName(), err)
	}
	t.Logf("created owner resource %q", owner.GetName())

	// Create a custom dependent resource.
	dependent := newCRDInstance(definition, ns.Name, names.SimpleNameGenerator.GenerateName("dependent"))
	link(t, owner, dependent)

	dependent, err = resourceClient.Create(dependent)
	if err != nil {
		t.Fatalf("failed to create dependent resource %q: %v", dependent.GetName(), err)
	}
	t.Logf("created dependent resource %q", dependent.GetName())

	// Delete the owner.
	foreground := metav1.DeletePropagationForeground
	err = resourceClient.Delete(owner.GetName(), &metav1.DeleteOptions{PropagationPolicy: &foreground})
	if err != nil {
		t.Fatalf("failed to delete owner resource %q: %v", owner.GetName(), err)
	}

	// Ensure the owner is deleted.
	if err := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
		_, err := resourceClient.Get(owner.GetName(), metav1.GetOptions{})
		return errors.IsNotFound(err), nil
	}); err != nil {
		t.Fatalf("failed waiting for owner resource %q to be deleted", owner.GetName())
	}

	// Ensure the dependent is deleted.
	_, err = resourceClient.Get(dependent.GetName(), metav1.GetOptions{})
	if err == nil {
		t.Fatalf("expected dependent %q to be deleted", dependent.GetName())
	} else {
		if !errors.IsNotFound(err) {
			t.Fatalf("unexpected error getting dependent %q: %v", dependent.GetName(), err)
		}
	}
}

// TestMixedRelationships ensures that owner/dependent relationships work
// between core and custom resources.
//
// TODO: Consider how this could be represented with table-style tests (e.g. a
// before/after expected object graph given a delete operation targetting a
// specific node in the before graph with certain delete options).
func TestMixedRelationships(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	clientSet, apiExtensionClient, clientPool := ctx.clientSet, ctx.apiExtensionClient, ctx.clientPool

	ns := createNamespaceOrDie("crd-mixed", clientSet, t)

	configMapClient := clientSet.Core().ConfigMaps(ns.Name)

	definition, resourceClient := createRandomCustomResourceDefinition(t, apiExtensionClient, clientPool, ns.Name)

	// Create a custom owner resource.
	customOwner, err := resourceClient.Create(newCRDInstance(definition, ns.Name, names.SimpleNameGenerator.GenerateName("owner")))
	if err != nil {
		t.Fatalf("failed to create owner: %v", err)
	}
	t.Logf("created custom owner %q", customOwner.GetName())

	// Create a core dependent resource.
	coreDependent := newConfigMap(ns.Name, names.SimpleNameGenerator.GenerateName("dependent"))
	link(t, customOwner, coreDependent)
	coreDependent, err = configMapClient.Create(coreDependent)
	if err != nil {
		t.Fatalf("failed to create dependent: %v", err)
	}
	t.Logf("created core dependent %q", coreDependent.GetName())

	// Create a core owner resource.
	coreOwner, err := configMapClient.Create(newConfigMap(ns.Name, names.SimpleNameGenerator.GenerateName("owner")))
	if err != nil {
		t.Fatalf("failed to create owner: %v", err)
	}
	t.Logf("created core owner %q: %#v", coreOwner.GetName(), coreOwner)

	// Create a custom dependent resource.
	customDependent := newCRDInstance(definition, ns.Name, names.SimpleNameGenerator.GenerateName("dependent"))
	coreOwner.TypeMeta.Kind = "ConfigMap"
	coreOwner.TypeMeta.APIVersion = "v1"
	link(t, coreOwner, customDependent)
	customDependent, err = resourceClient.Create(customDependent)
	if err != nil {
		t.Fatalf("failed to create dependent: %v", err)
	}
	t.Logf("created custom dependent %q", customDependent.GetName())

	// Delete the custom owner.
	foreground := metav1.DeletePropagationForeground
	err = resourceClient.Delete(customOwner.GetName(), &metav1.DeleteOptions{PropagationPolicy: &foreground})
	if err != nil {
		t.Fatalf("failed to delete owner resource %q: %v", customOwner.GetName(), err)
	}

	// Ensure the owner is deleted.
	if err := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
		_, err := resourceClient.Get(customOwner.GetName(), metav1.GetOptions{})
		return errors.IsNotFound(err), nil
	}); err != nil {
		t.Fatalf("failed waiting for owner resource %q to be deleted", customOwner.GetName())
	}

	// Ensure the dependent is deleted.
	_, err = resourceClient.Get(coreDependent.GetName(), metav1.GetOptions{})
	if err == nil {
		t.Fatalf("expected dependent %q to be deleted", coreDependent.GetName())
	} else {
		if !errors.IsNotFound(err) {
			t.Fatalf("unexpected error getting dependent %q: %v", coreDependent.GetName(), err)
		}
	}

	// Delete the core owner.
	err = configMapClient.Delete(coreOwner.GetName(), &metav1.DeleteOptions{PropagationPolicy: &foreground})
	if err != nil {
		t.Fatalf("failed to delete owner resource %q: %v", coreOwner.GetName(), err)
	}

	// Ensure the owner is deleted.
	if err := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
		_, err := configMapClient.Get(coreOwner.GetName(), metav1.GetOptions{})
		return errors.IsNotFound(err), nil
	}); err != nil {
		t.Fatalf("failed waiting for owner resource %q to be deleted", coreOwner.GetName())
	}

	// Ensure the dependent is deleted.
	_, err = resourceClient.Get(customDependent.GetName(), metav1.GetOptions{})
	if err == nil {
		t.Fatalf("expected dependent %q to be deleted", customDependent.GetName())
	} else {
		if !errors.IsNotFound(err) {
			t.Fatalf("unexpected error getting dependent %q: %v", customDependent.GetName(), err)
		}
	}
}

// TestCRDDeletionCascading ensures propagating deletion of a custom resource
// definition with an instance that owns a core resource.
func TestCRDDeletionCascading(t *testing.T) {
	ctx := setup(t, 5)
	defer ctx.tearDown()

	clientSet, apiExtensionClient, clientPool := ctx.clientSet, ctx.apiExtensionClient, ctx.clientPool

	ns := createNamespaceOrDie("crd-mixed", clientSet, t)

	configMapClient := clientSet.Core().ConfigMaps(ns.Name)

	definition, resourceClient := createRandomCustomResourceDefinition(t, apiExtensionClient, clientPool, ns.Name)

	// Create a custom owner resource.
	owner, err := resourceClient.Create(newCRDInstance(definition, ns.Name, names.SimpleNameGenerator.GenerateName("owner")))
	if err != nil {
		t.Fatalf("failed to create owner: %v", err)
	}
	t.Logf("created owner %q", owner.GetName())

	// Create a core dependent resource.
	dependent := newConfigMap(ns.Name, names.SimpleNameGenerator.GenerateName("dependent"))
	link(t, owner, dependent)
	dependent, err = configMapClient.Create(dependent)
	if err != nil {
		t.Fatalf("failed to create dependent: %v", err)
	}
	t.Logf("created dependent %q", dependent.GetName())

	time.Sleep(ctx.syncPeriod + 5*time.Second)

	// Delete the definition, which should cascade to the owner and ultimately its dependents.
	if err := apiextensionstestserver.DeleteCustomResourceDefinition(definition, apiExtensionClient); err != nil {
		t.Fatalf("failed to delete %q: %v", definition.Name, err)
	}

	// Ensure the owner is deleted.
	if err := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
		_, err := resourceClient.Get(owner.GetName(), metav1.GetOptions{})
		return errors.IsNotFound(err), nil
	}); err != nil {
		t.Fatalf("failed waiting for owner %q to be deleted", owner.GetName())
	}

	// Ensure the dependent is deleted.
	if err := wait.Poll(5*time.Second, 60*time.Second, func() (bool, error) {
		_, err := configMapClient.Get(dependent.GetName(), metav1.GetOptions{})
		return errors.IsNotFound(err), nil
	}); err != nil {
		t.Fatalf("failed waiting for dependent %q (owned by %q) to be deleted", dependent.GetName(), owner.GetName())
	}
}
