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

package storage

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"
	"k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1alpha1 "k8s.io/apimachinery/pkg/apis/meta/v1alpha1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
	storeerr "k8s.io/apiserver/pkg/storage/errors"
	etcdtesting "k8s.io/apiserver/pkg/storage/etcd/testing"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	utilfeaturetesting "k8s.io/apiserver/pkg/util/feature/testing"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/registry/registrytest"
	"k8s.io/kubernetes/pkg/securitycontext"
)

func newStorage(t *testing.T) (*REST, *BindingREST, *StatusREST, *etcdtesting.EtcdTestServer) {
	etcdStorage, server := registrytest.NewEtcdStorage(t, "")
	restOptions := generic.RESTOptions{
		StorageConfig:           etcdStorage,
		Decorator:               generic.UndecoratedStorage,
		DeleteCollectionWorkers: 3,
		ResourcePrefix:          "pods",
	}
	storage := NewStorage(restOptions, nil, nil, nil)
	return storage.Pod, storage.Binding, storage.Status, server
}

func validNewPod() *api.Pod {
	grace := int64(30)
	return &api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: api.PodSpec{
			RestartPolicy: api.RestartPolicyAlways,
			DNSPolicy:     api.DNSClusterFirst,

			TerminationGracePeriodSeconds: &grace,
			Containers: []api.Container{
				{
					Name:            "foo",
					Image:           "test",
					ImagePullPolicy: api.PullAlways,

					TerminationMessagePath:   api.TerminationMessagePathDefault,
					TerminationMessagePolicy: api.TerminationMessageReadFile,
					SecurityContext:          securitycontext.ValidInternalSecurityContextWithContainerDefaults(),
				},
			},
			SecurityContext: &api.PodSecurityContext{},
			SchedulerName:   api.DefaultSchedulerName,
		},
	}
}

func validChangedPod() *api.Pod {
	pod := validNewPod()
	pod.Labels = map[string]string{
		"foo": "bar",
	}
	return pod
}

func TestCreate(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	test := registrytest.New(t, storage.Store)
	pod := validNewPod()
	pod.ObjectMeta = metav1.ObjectMeta{}
	// Make an invalid pod with an an incorrect label.
	invalidPod := validNewPod()
	invalidPod.Namespace = test.TestNamespace()
	invalidPod.Labels = map[string]string{
		"invalid/label/to/cause/validation/failure": "bar",
	}
	test.TestCreate(
		// valid
		pod,
		// invalid (empty contains list)
		&api.Pod{
			Spec: api.PodSpec{
				Containers: []api.Container{},
			},
		},
		// invalid (invalid labels)
		invalidPod,
	)
}

func TestUpdate(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	test := registrytest.New(t, storage.Store)
	test.TestUpdate(
		// valid
		validNewPod(),
		// updateFunc
		func(obj runtime.Object) runtime.Object {
			object := obj.(*api.Pod)
			object.Labels = map[string]string{"a": "b"}
			return object
		},
	)
}

func TestDelete(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	test := registrytest.New(t, storage.Store).ReturnDeletedObject()
	test.TestDelete(validNewPod())

	scheduledPod := validNewPod()
	scheduledPod.Spec.NodeName = "some-node"
	test.TestDeleteGraceful(scheduledPod, 30)
}

type FailDeletionStorage struct {
	storage.Interface
	Called *bool
}

func (f FailDeletionStorage) Delete(ctx context.Context, key string, out runtime.Object, precondition *storage.Preconditions) error {
	*f.Called = true
	return storage.NewKeyNotFoundError(key, 0)
}

func newFailDeleteStorage(t *testing.T, called *bool) (*REST, *etcdtesting.EtcdTestServer) {
	etcdStorage, server := registrytest.NewEtcdStorage(t, "")
	restOptions := generic.RESTOptions{
		StorageConfig:           etcdStorage,
		Decorator:               generic.UndecoratedStorage,
		DeleteCollectionWorkers: 3,
		ResourcePrefix:          "pods",
	}
	storage := NewStorage(restOptions, nil, nil, nil)
	storage.Pod.Store.Storage = FailDeletionStorage{storage.Pod.Store.Storage, called}
	return storage.Pod, server
}

func TestIgnoreDeleteNotFound(t *testing.T) {
	pod := validNewPod()
	testContext := genericapirequest.WithNamespace(genericapirequest.NewContext(), metav1.NamespaceDefault)
	called := false
	registry, server := newFailDeleteStorage(t, &called)
	defer server.Terminate(t)
	defer registry.Store.DestroyFunc()

	// should fail if pod A is not created yet.
	_, _, err := registry.Delete(testContext, pod.Name, nil)
	if !errors.IsNotFound(err) {
		t.Errorf("Unexpected error: %v", err)
	}

	// create pod
	_, err = registry.Create(testContext, pod, false)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// delete object with grace period 0, storage will return NotFound, but the
	// registry shouldn't get any error since we ignore the NotFound error.
	zero := int64(0)
	opt := &metav1.DeleteOptions{GracePeriodSeconds: &zero}
	obj, _, err := registry.Delete(testContext, pod.Name, opt)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !called {
		t.Fatalf("expect the overriding Delete method to be called")
	}
	deletedPod, ok := obj.(*api.Pod)
	if !ok {
		t.Fatalf("expect a pod is returned")
	}
	if deletedPod.DeletionTimestamp == nil {
		t.Errorf("expect the DeletionTimestamp to be set")
	}
	if deletedPod.DeletionGracePeriodSeconds == nil {
		t.Fatalf("expect the DeletionGracePeriodSeconds to be set")
	}
	if *deletedPod.DeletionGracePeriodSeconds != 0 {
		t.Errorf("expect the DeletionGracePeriodSeconds to be 0, got %v", *deletedPod.DeletionTimestamp)
	}
}

func TestCreateSetsFields(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	pod := validNewPod()
	_, err := storage.Create(genericapirequest.NewDefaultContext(), pod, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := genericapirequest.NewDefaultContext()
	object, err := storage.Get(ctx, "foo", &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	actual := object.(*api.Pod)
	if actual.Name != pod.Name {
		t.Errorf("unexpected pod: %#v", actual)
	}
	if len(actual.UID) == 0 {
		t.Errorf("expected pod UID to be set: %#v", actual)
	}
}

func TestResourceLocation(t *testing.T) {
	expectedIP := "1.2.3.4"
	testCases := []struct {
		pod      api.Pod
		query    string
		location string
	}{
		{
			pod: api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Status:     api.PodStatus{PodIP: expectedIP},
			},
			query:    "foo",
			location: expectedIP,
		},
		{
			pod: api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Status:     api.PodStatus{PodIP: expectedIP},
			},
			query:    "foo:12345",
			location: expectedIP + ":12345",
		},
		{
			pod: api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: api.PodSpec{
					Containers: []api.Container{
						{Name: "ctr"},
					},
				},
				Status: api.PodStatus{PodIP: expectedIP},
			},
			query:    "foo",
			location: expectedIP,
		},
		{
			pod: api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: api.PodSpec{
					Containers: []api.Container{
						{Name: "ctr", Ports: []api.ContainerPort{{ContainerPort: 9376}}},
					},
				},
				Status: api.PodStatus{PodIP: expectedIP},
			},
			query:    "foo",
			location: expectedIP + ":9376",
		},
		{
			pod: api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: api.PodSpec{
					Containers: []api.Container{
						{Name: "ctr", Ports: []api.ContainerPort{{ContainerPort: 9376}}},
					},
				},
				Status: api.PodStatus{PodIP: expectedIP},
			},
			query:    "foo:12345",
			location: expectedIP + ":12345",
		},
		{
			pod: api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: api.PodSpec{
					Containers: []api.Container{
						{Name: "ctr1"},
						{Name: "ctr2", Ports: []api.ContainerPort{{ContainerPort: 9376}}},
					},
				},
				Status: api.PodStatus{PodIP: expectedIP},
			},
			query:    "foo",
			location: expectedIP + ":9376",
		},
		{
			pod: api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: api.PodSpec{
					Containers: []api.Container{
						{Name: "ctr1", Ports: []api.ContainerPort{{ContainerPort: 9376}}},
						{Name: "ctr2", Ports: []api.ContainerPort{{ContainerPort: 1234}}},
					},
				},
				Status: api.PodStatus{PodIP: expectedIP},
			},
			query:    "foo",
			location: expectedIP + ":9376",
		},
	}

	ctx := genericapirequest.NewDefaultContext()
	for _, tc := range testCases {
		storage, _, _, server := newStorage(t)
		key, _ := storage.KeyFunc(ctx, tc.pod.Name)
		if err := storage.Storage.Create(ctx, key, &tc.pod, nil, 0); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		redirector := rest.Redirector(storage)
		location, _, err := redirector.ResourceLocation(genericapirequest.NewDefaultContext(), tc.query)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if location == nil {
			t.Errorf("Unexpected nil: %v", location)
		}

		if location.Scheme != "" {
			t.Errorf("Expected '%v', but got '%v'", "", location.Scheme)
		}
		if location.Host != tc.location {
			t.Errorf("Expected %v, but got %v", tc.location, location.Host)
		}
		server.Terminate(t)
	}
}

func TestGet(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	test := registrytest.New(t, storage.Store)
	test.TestGet(validNewPod())
}

func TestList(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	test := registrytest.New(t, storage.Store)
	test.TestList(validNewPod())
}

func TestWatch(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	test := registrytest.New(t, storage.Store)
	test.TestWatch(
		validNewPod(),
		// matching labels
		[]labels.Set{},
		// not matching labels
		[]labels.Set{
			{"foo": "bar"},
		},
		// matching fields
		[]fields.Set{
			{"metadata.name": "foo"},
		},
		// not matchin fields
		[]fields.Set{
			{"metadata.name": "bar"},
		},
	)
}

func TestConvertToTableList(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	columns := []metav1alpha1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Ready", Type: "string", Description: "The aggregate readiness state of this pod for accepting traffic."},
		{Name: "Status", Type: "string", Description: "The aggregate status of the containers in this pod."},
		{Name: "Restarts", Type: "integer", Description: "The number of times the containers in this pod have been restarted."},
		{Name: "Age", Type: "string", Description: metav1.ObjectMeta{}.SwaggerDoc()["creationTimestamp"]},
		{Name: "IP", Type: "string", Priority: 1, Description: v1.PodStatus{}.SwaggerDoc()["podIP"]},
		{Name: "Node", Type: "string", Priority: 1, Description: v1.PodSpec{}.SwaggerDoc()["nodeName"]},
	}

	pod1 := &api.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "foo", CreationTimestamp: metav1.NewTime(time.Now().Add(-370 * 24 * time.Hour))},
		Spec: api.PodSpec{
			Containers: []api.Container{
				{Name: "ctr1"},
				{Name: "ctr2", Ports: []api.ContainerPort{{ContainerPort: 9376}}},
			},
			NodeName: "test-node",
		},
		Status: api.PodStatus{
			PodIP: "10.1.2.3",
			Phase: api.PodPending,
			ContainerStatuses: []api.ContainerStatus{
				{Name: "ctr1", State: api.ContainerState{Running: &api.ContainerStateRunning{}}, RestartCount: 10, Ready: true},
				{Name: "ctr2", State: api.ContainerState{Waiting: &api.ContainerStateWaiting{}}, RestartCount: 0},
			},
		},
	}

	testCases := []struct {
		in  runtime.Object
		out *metav1alpha1.Table
		err bool
	}{
		{
			in:  nil,
			err: true,
		},
		{
			in: &api.Pod{},
			out: &metav1alpha1.Table{
				ColumnDefinitions: columns,
				Rows: []metav1alpha1.TableRow{
					{Cells: []interface{}{"", "0/0", "", 0, "<unknown>", "<none>", "<none>"}, Object: runtime.RawExtension{Object: &api.Pod{}}},
				},
			},
		},
		{
			in: pod1,
			out: &metav1alpha1.Table{
				ColumnDefinitions: columns,
				Rows: []metav1alpha1.TableRow{
					{Cells: []interface{}{"foo", "1/2", "Pending", 10, "1y", "10.1.2.3", "test-node"}, Object: runtime.RawExtension{Object: pod1}},
				},
			},
		},
		{
			in:  &api.PodList{},
			out: &metav1alpha1.Table{ColumnDefinitions: columns},
		},
	}
	for i, test := range testCases {
		out, err := storage.ConvertToTable(ctx, test.in, nil)
		if err != nil {
			if test.err {
				continue
			}
			t.Errorf("%d: error: %v", i, err)
			continue
		}
		if !apiequality.Semantic.DeepEqual(test.out, out) {
			t.Errorf("%d: mismatch: %s", i, diff.ObjectReflectDiff(test.out, out))
		}
	}
}

func TestEtcdCreate(t *testing.T) {
	storage, bindingStorage, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()
	_, err := storage.Create(ctx, validNewPod(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Suddenly, a wild scheduler appears:
	_, err = bindingStorage.Create(ctx, &api.Binding{
		ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "foo"},
		Target:     api.ObjectReference{Name: "machine"},
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = storage.Get(ctx, "foo", &metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
}

// Ensure that when scheduler creates a binding for a pod that has already been deleted
// by the API server, API server returns not-found error.
func TestEtcdCreateBindingNoPod(t *testing.T) {
	storage, bindingStorage, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	// Assume that a pod has undergone the following:
	// - Create (apiserver)
	// - Schedule (scheduler)
	// - Delete (apiserver)
	_, err := bindingStorage.Create(ctx, &api.Binding{
		ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "foo"},
		Target:     api.ObjectReference{Name: "machine"},
	}, false)
	if err == nil {
		t.Fatalf("Expected not-found-error but got nothing")
	}
	if !errors.IsNotFound(storeerr.InterpretGetError(err, api.Resource("pods"), "foo")) {
		t.Fatalf("Unexpected error returned: %#v", err)
	}

	_, err = storage.Get(ctx, "foo", &metav1.GetOptions{})
	if err == nil {
		t.Fatalf("Expected not-found-error but got nothing")
	}
	if !errors.IsNotFound(storeerr.InterpretGetError(err, api.Resource("pods"), "foo")) {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestEtcdCreateFailsWithoutNamespace(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	pod := validNewPod()
	pod.Namespace = ""
	_, err := storage.Create(genericapirequest.NewContext(), pod, false)
	// Accept "namespace" or "Namespace".
	if err == nil || !strings.Contains(err.Error(), "amespace") {
		t.Fatalf("expected error that namespace was missing from context, got: %v", err)
	}
}

func TestEtcdCreateWithContainersNotFound(t *testing.T) {
	storage, bindingStorage, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()
	_, err := storage.Create(ctx, validNewPod(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Suddenly, a wild scheduler appears:
	_, err = bindingStorage.Create(ctx, &api.Binding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   metav1.NamespaceDefault,
			Name:        "foo",
			Annotations: map[string]string{"label1": "value1"},
		},
		Target: api.ObjectReference{Name: "machine"},
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	obj, err := storage.Get(ctx, "foo", &metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
	pod := obj.(*api.Pod)

	if !(pod.Annotations != nil && pod.Annotations["label1"] == "value1") {
		t.Fatalf("Pod annotations don't match the expected: %v", pod.Annotations)
	}
}

func TestEtcdCreateWithConflict(t *testing.T) {
	storage, bindingStorage, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	_, err := storage.Create(ctx, validNewPod(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Suddenly, a wild scheduler appears:
	binding := api.Binding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   metav1.NamespaceDefault,
			Name:        "foo",
			Annotations: map[string]string{"label1": "value1"},
		},
		Target: api.ObjectReference{Name: "machine"},
	}
	_, err = bindingStorage.Create(ctx, &binding, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = bindingStorage.Create(ctx, &binding, false)
	if err == nil || !errors.IsConflict(err) {
		t.Fatalf("expected resource conflict error, not: %v", err)
	}
}

func TestEtcdCreateWithExistingContainers(t *testing.T) {
	storage, bindingStorage, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()
	_, err := storage.Create(ctx, validNewPod(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Suddenly, a wild scheduler appears:
	_, err = bindingStorage.Create(ctx, &api.Binding{
		ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "foo"},
		Target:     api.ObjectReference{Name: "machine"},
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = storage.Get(ctx, "foo", &metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}
}

func TestEtcdCreateBinding(t *testing.T) {
	ctx := genericapirequest.NewDefaultContext()

	testCases := map[string]struct {
		binding api.Binding
		errOK   func(error) bool
	}{
		"noName": {
			binding: api.Binding{
				ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "foo"},
				Target:     api.ObjectReference{},
			},
			errOK: func(err error) bool { return err != nil },
		},
		"badKind": {
			binding: api.Binding{
				ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "foo"},
				Target:     api.ObjectReference{Name: "machine1", Kind: "unknown"},
			},
			errOK: func(err error) bool { return err != nil },
		},
		"emptyKind": {
			binding: api.Binding{
				ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "foo"},
				Target:     api.ObjectReference{Name: "machine2"},
			},
			errOK: func(err error) bool { return err == nil },
		},
		"kindNode": {
			binding: api.Binding{
				ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "foo"},
				Target:     api.ObjectReference{Name: "machine3", Kind: "Node"},
			},
			errOK: func(err error) bool { return err == nil },
		},
	}
	for k, test := range testCases {
		storage, bindingStorage, _, server := newStorage(t)

		if _, err := storage.Create(ctx, validNewPod(), false); err != nil {
			t.Fatalf("%s: unexpected error: %v", k, err)
		}
		if _, err := bindingStorage.Create(ctx, &test.binding, false); !test.errOK(err) {
			t.Errorf("%s: unexpected error: %v", k, err)
		} else if err == nil {
			// If bind succeeded, verify Host field in pod's Spec.
			pod, err := storage.Get(ctx, validNewPod().ObjectMeta.Name, &metav1.GetOptions{})
			if err != nil {
				t.Errorf("%s: unexpected error: %v", k, err)
			} else if pod.(*api.Pod).Spec.NodeName != test.binding.Target.Name {
				t.Errorf("%s: expected: %v, got: %v", k, pod.(*api.Pod).Spec.NodeName, test.binding.Target.Name)
			}
		}
		storage.Store.DestroyFunc()
		server.Terminate(t)
	}
}

func TestEtcdUpdateUninitialized(t *testing.T) {
	defer utilfeaturetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.Initializers, true)()
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	pod := validNewPod()
	// add pending initializers to the pod
	pod.ObjectMeta.Initializers = &metav1.Initializers{Pending: []metav1.Initializer{{Name: "init.k8s.io"}}}
	if _, err := storage.Create(ctx, pod, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	podIn := *pod
	// only uninitialized pod is allowed to add containers via update
	podIn.Spec.Containers = append(podIn.Spec.Containers, api.Container{
		Name:                     "foo2",
		Image:                    "test",
		ImagePullPolicy:          api.PullAlways,
		TerminationMessagePath:   api.TerminationMessagePathDefault,
		TerminationMessagePolicy: api.TerminationMessageReadFile,
		SecurityContext:          securitycontext.ValidInternalSecurityContextWithContainerDefaults(),
	})
	podIn.ObjectMeta.Initializers = nil

	_, _, err := storage.Update(ctx, podIn.Name, rest.DefaultUpdatedObjectInfo(&podIn, api.Scheme))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	obj, err := storage.Get(ctx, podIn.ObjectMeta.Name, &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	podOut := obj.(*api.Pod)
	if podOut.GetInitializers() != nil {
		t.Errorf("expect nil initializers, got %v", podOut.ObjectMeta.Initializers)
	}
	if !apiequality.Semantic.DeepEqual(podIn.Spec.Containers, podOut.Spec.Containers) {
		t.Errorf("objects differ: %v", diff.ObjectDiff(podOut, &podIn))
	}
}

func TestEtcdStatusUpdateUninitialized(t *testing.T) {
	defer utilfeaturetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.Initializers, true)()
	storage, _, statusStorage, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	pod := validNewPod()
	// add pending initializers to the pod
	pod.ObjectMeta.Initializers = &metav1.Initializers{Pending: []metav1.Initializer{{Name: "init.k8s.io"}}}
	if _, err := storage.Create(ctx, pod, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	podIn := *pod
	// only uninitialized pod is allowed to add containers via update
	podIn.Status.Phase = api.PodRunning
	podIn.ObjectMeta.Initializers = nil

	_, _, err := statusStorage.Update(ctx, podIn.Name, rest.DefaultUpdatedObjectInfo(&podIn, api.Scheme))
	expected := "Forbidden: must not update status when the object is uninitialized"
	if err == nil {
		t.Fatalf("Unexpected no err, expected %q", expected)
	}
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("unexpected error: %v, expected %q", err, expected)
	}
}

func TestEtcdUpdateNotScheduled(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	if _, err := storage.Create(ctx, validNewPod(), false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	podIn := validChangedPod()
	_, _, err := storage.Update(ctx, podIn.Name, rest.DefaultUpdatedObjectInfo(podIn, api.Scheme))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	obj, err := storage.Get(ctx, validNewPod().ObjectMeta.Name, &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	podOut := obj.(*api.Pod)
	// validChangedPod only changes the Labels, so were checking the update was valid
	if !apiequality.Semantic.DeepEqual(podIn.Labels, podOut.Labels) {
		t.Errorf("objects differ: %v", diff.ObjectDiff(podOut, podIn))
	}
}

func TestEtcdUpdateScheduled(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	key, _ := storage.KeyFunc(ctx, "foo")
	err := storage.Storage.Create(ctx, key, &api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: api.PodSpec{
			NodeName: "machine",
			Containers: []api.Container{
				{
					Name:            "foobar",
					Image:           "foo:v1",
					SecurityContext: securitycontext.ValidInternalSecurityContextWithContainerDefaults(),
				},
			},
			SecurityContext: &api.PodSecurityContext{},
			SchedulerName:   api.DefaultSchedulerName,
		},
	}, nil, 1)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	grace := int64(30)
	podIn := api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: api.PodSpec{
			NodeName: "machine",
			Containers: []api.Container{{
				Name:                     "foobar",
				Image:                    "foo:v2",
				ImagePullPolicy:          api.PullIfNotPresent,
				TerminationMessagePath:   api.TerminationMessagePathDefault,
				TerminationMessagePolicy: api.TerminationMessageReadFile,
				SecurityContext:          securitycontext.ValidInternalSecurityContextWithContainerDefaults(),
			}},
			RestartPolicy: api.RestartPolicyAlways,
			DNSPolicy:     api.DNSClusterFirst,

			TerminationGracePeriodSeconds: &grace,
			SecurityContext:               &api.PodSecurityContext{},
			SchedulerName:                 api.DefaultSchedulerName,
		},
	}
	_, _, err = storage.Update(ctx, podIn.Name, rest.DefaultUpdatedObjectInfo(&podIn, api.Scheme))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	obj, err := storage.Get(ctx, "foo", &metav1.GetOptions{})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	podOut := obj.(*api.Pod)
	// Check to verify the Spec and Label updates match from change above.  Those are the fields changed.
	if !apiequality.Semantic.DeepEqual(podOut.Spec, podIn.Spec) || !apiequality.Semantic.DeepEqual(podOut.Labels, podIn.Labels) {
		t.Errorf("objects differ: %v", diff.ObjectDiff(podOut, podIn))
	}

}

func TestEtcdUpdateStatus(t *testing.T) {
	storage, _, statusStorage, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	ctx := genericapirequest.NewDefaultContext()

	key, _ := storage.KeyFunc(ctx, "foo")
	podStart := api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: api.PodSpec{
			NodeName: "machine",
			Containers: []api.Container{
				{
					Image:           "foo:v1",
					SecurityContext: securitycontext.ValidInternalSecurityContextWithContainerDefaults(),
				},
			},
			SecurityContext: &api.PodSecurityContext{},
			SchedulerName:   api.DefaultSchedulerName,
		},
	}
	err := storage.Storage.Create(ctx, key, &podStart, nil, 0)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	podIn := api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: api.PodSpec{
			NodeName: "machine",
			Containers: []api.Container{
				{
					Image:                  "foo:v2",
					ImagePullPolicy:        api.PullIfNotPresent,
					TerminationMessagePath: api.TerminationMessagePathDefault,
				},
			},
			SecurityContext: &api.PodSecurityContext{},
			SchedulerName:   api.DefaultSchedulerName,
		},
		Status: api.PodStatus{
			Phase:   api.PodRunning,
			PodIP:   "127.0.0.1",
			Message: "is now scheduled",
		},
	}

	expected := podStart
	expected.ResourceVersion = "2"
	grace := int64(30)
	expected.Spec.TerminationGracePeriodSeconds = &grace
	expected.Spec.RestartPolicy = api.RestartPolicyAlways
	expected.Spec.DNSPolicy = api.DNSClusterFirst
	expected.Spec.Containers[0].ImagePullPolicy = api.PullIfNotPresent
	expected.Spec.Containers[0].TerminationMessagePath = api.TerminationMessagePathDefault
	expected.Spec.Containers[0].TerminationMessagePolicy = api.TerminationMessageReadFile
	expected.Labels = podIn.Labels
	expected.Status = podIn.Status

	_, _, err = statusStorage.Update(ctx, podIn.Name, rest.DefaultUpdatedObjectInfo(&podIn, api.Scheme))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	obj, err := storage.Get(ctx, "foo", &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	podOut := obj.(*api.Pod)
	// Check to verify the Label, and Status updates match from change above.  Those are the fields changed.
	if !apiequality.Semantic.DeepEqual(podOut.Spec, expected.Spec) ||
		!apiequality.Semantic.DeepEqual(podOut.Labels, expected.Labels) ||
		!apiequality.Semantic.DeepEqual(podOut.Status, expected.Status) {
		t.Errorf("objects differ: %v", diff.ObjectDiff(podOut, expected))
	}
}

func TestShortNames(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	expected := []string{"po"}
	registrytest.AssertShortNames(t, storage, expected)
}

func TestCategories(t *testing.T) {
	storage, _, _, server := newStorage(t)
	defer server.Terminate(t)
	defer storage.Store.DestroyFunc()
	expected := []string{"all"}
	registrytest.AssertCategories(t, storage, expected)
}
