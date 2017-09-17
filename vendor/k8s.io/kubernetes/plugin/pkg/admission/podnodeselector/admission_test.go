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

package podnodeselector

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
	informers "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion"
	kubeadmission "k8s.io/kubernetes/pkg/kubeapiserver/admission"
)

// TestPodAdmission verifies various scenarios involving pod/namespace/global node label selectors
func TestPodAdmission(t *testing.T) {
	namespace := &api.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testNamespace",
			Namespace: "",
		},
	}

	mockClient := &fake.Clientset{}
	handler, informerFactory, err := newHandlerForTest(mockClient)
	if err != nil {
		t.Errorf("unexpected error initializing handler: %v", err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)

	pod := &api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "testPod", Namespace: "testNamespace"},
	}

	oldPod := *pod
	oldPod.Initializers = &metav1.Initializers{Pending: []metav1.Initializer{{Name: "init"}}}
	oldPod.Spec.NodeSelector = map[string]string{
		"old": "true",
	}

	tests := []struct {
		defaultNodeSelector             string
		namespaceNodeSelector           string
		whitelist                       string
		podNodeSelector                 map[string]string
		mergedNodeSelector              labels.Set
		ignoreTestNamespaceNodeSelector bool
		admit                           bool
		testName                        string
	}{
		{
			defaultNodeSelector:             "",
			podNodeSelector:                 map[string]string{},
			mergedNodeSelector:              labels.Set{},
			ignoreTestNamespaceNodeSelector: true,
			admit:    true,
			testName: "No node selectors",
		},
		{
			defaultNodeSelector:             "infra = false",
			podNodeSelector:                 map[string]string{},
			mergedNodeSelector:              labels.Set{"infra": "false"},
			ignoreTestNamespaceNodeSelector: true,
			admit:    true,
			testName: "Default node selector and no conflicts",
		},
		{
			defaultNodeSelector:   "",
			namespaceNodeSelector: " infra = false ",
			podNodeSelector:       map[string]string{},
			mergedNodeSelector:    labels.Set{"infra": "false"},
			admit:                 true,
			testName:              "TestNamespace node selector with whitespaces and no conflicts",
		},
		{
			defaultNodeSelector:   "infra = false",
			namespaceNodeSelector: "infra=true",
			podNodeSelector:       map[string]string{},
			mergedNodeSelector:    labels.Set{"infra": "true"},
			admit:                 true,
			testName:              "Default and namespace node selector, no conflicts",
		},
		{
			defaultNodeSelector:   "infra = false",
			namespaceNodeSelector: "",
			podNodeSelector:       map[string]string{},
			mergedNodeSelector:    labels.Set{},
			admit:                 true,
			testName:              "Empty namespace node selector and no conflicts",
		},
		{
			defaultNodeSelector:   "infra = false",
			namespaceNodeSelector: "infra=true",
			podNodeSelector:       map[string]string{"env": "test"},
			mergedNodeSelector:    labels.Set{"infra": "true", "env": "test"},
			admit:                 true,
			testName:              "TestNamespace and pod node selector, no conflicts",
		},
		{
			defaultNodeSelector:   "env = test",
			namespaceNodeSelector: "infra=true",
			podNodeSelector:       map[string]string{"infra": "false"},
			admit:                 false,
			testName:              "Conflicting pod and namespace node selector, one label",
		},
		{
			defaultNodeSelector:   "env=dev",
			namespaceNodeSelector: "infra=false, env = test",
			podNodeSelector:       map[string]string{"env": "dev", "color": "blue"},
			admit:                 false,
			testName:              "Conflicting pod and namespace node selector, multiple labels",
		},
		{
			defaultNodeSelector:   "env=dev",
			namespaceNodeSelector: "infra=false, env = dev",
			whitelist:             "env=dev, infra=false, color=blue",
			podNodeSelector:       map[string]string{"env": "dev", "color": "blue"},
			mergedNodeSelector:    labels.Set{"infra": "false", "env": "dev", "color": "blue"},
			admit:                 true,
			testName:              "Merged pod node selectors satisfy the whitelist",
		},
		{
			defaultNodeSelector:   "env=dev",
			namespaceNodeSelector: "infra=false, env = dev",
			whitelist:             "env=dev, infra=true, color=blue",
			podNodeSelector:       map[string]string{"env": "dev", "color": "blue"},
			admit:                 false,
			testName:              "Merged pod node selectors conflict with the whitelist",
		},
		{
			defaultNodeSelector:             "env=dev",
			ignoreTestNamespaceNodeSelector: true,
			whitelist:                       "env=prd",
			podNodeSelector:                 map[string]string{},
			admit:                           false,
			testName:                        "Default node selector conflict with the whitelist",
		},
	}
	for _, test := range tests {
		if !test.ignoreTestNamespaceNodeSelector {
			namespace.ObjectMeta.Annotations = map[string]string{"scheduler.alpha.kubernetes.io/node-selector": test.namespaceNodeSelector}
			informerFactory.Core().InternalVersion().Namespaces().Informer().GetStore().Update(namespace)
		}
		handler.clusterNodeSelectors = make(map[string]string)
		handler.clusterNodeSelectors["clusterDefaultNodeSelector"] = test.defaultNodeSelector
		handler.clusterNodeSelectors[namespace.Name] = test.whitelist
		pod.Spec = api.PodSpec{NodeSelector: test.podNodeSelector}

		err := handler.Admit(admission.NewAttributesRecord(pod, nil, api.Kind("Pod").WithVersion("version"), "testNamespace", namespace.ObjectMeta.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
		if test.admit && err != nil {
			t.Errorf("Test: %s, expected no error but got: %s", test.testName, err)
		} else if !test.admit && err == nil {
			t.Errorf("Test: %s, expected an error", test.testName)
		}
		if test.admit && !labels.Equals(test.mergedNodeSelector, labels.Set(pod.Spec.NodeSelector)) {
			t.Errorf("Test: %s, expected: %s but got: %s", test.testName, test.mergedNodeSelector, pod.Spec.NodeSelector)
		}

		// handles update of uninitialized pod like it's newly created.
		err = handler.Admit(admission.NewAttributesRecord(pod, &oldPod, api.Kind("Pod").WithVersion("version"), "testNamespace", namespace.ObjectMeta.Name, api.Resource("pods").WithVersion("version"), "", admission.Update, nil))
		if test.admit && err != nil {
			t.Errorf("Test: %s, expected no error but got: %s", test.testName, err)
		} else if !test.admit && err == nil {
			t.Errorf("Test: %s, expected an error", test.testName)
		}
		if test.admit && !labels.Equals(test.mergedNodeSelector, labels.Set(pod.Spec.NodeSelector)) {
			t.Errorf("Test: %s, expected: %s but got: %s", test.testName, test.mergedNodeSelector, pod.Spec.NodeSelector)
		}
	}
}

func TestHandles(t *testing.T) {
	for op, shouldHandle := range map[admission.Operation]bool{
		admission.Create:  true,
		admission.Update:  true,
		admission.Connect: false,
		admission.Delete:  false,
	} {
		nodeEnvionment := NewPodNodeSelector(nil)
		if e, a := shouldHandle, nodeEnvionment.Handles(op); e != a {
			t.Errorf("%v: shouldHandle=%t, handles=%t", op, e, a)
		}
	}
}

func TestIgnoreUpdatingInitializedPod(t *testing.T) {
	mockClient := &fake.Clientset{}
	handler, informerFactory, err := newHandlerForTest(mockClient)
	if err != nil {
		t.Errorf("unexpected error initializing handler: %v", err)
	}
	handler.SetReadyFunc(func() bool { return true })

	podNodeSelector := map[string]string{"infra": "false"}
	pod := &api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "testPod", Namespace: "testNamespace"},
		Spec:       api.PodSpec{NodeSelector: podNodeSelector},
	}
	// this conflicts with podNodeSelector
	namespaceNodeSelector := "infra=true"
	namespace := &api.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "testNamespace",
			Namespace:   "",
			Annotations: map[string]string{"scheduler.alpha.kubernetes.io/node-selector": namespaceNodeSelector},
		},
	}
	err = informerFactory.Core().InternalVersion().Namespaces().Informer().GetStore().Update(namespace)
	if err != nil {
		t.Fatal(err)
	}

	// if the update of initialized pod is not ignored, an error will be returned because the pod's nodeSelector conflicts with namespace's nodeSelector.
	err = handler.Admit(admission.NewAttributesRecord(pod, pod, api.Kind("Pod").WithVersion("version"), "testNamespace", namespace.ObjectMeta.Name, api.Resource("pods").WithVersion("version"), "", admission.Update, nil))
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

// newHandlerForTest returns the admission controller configured for testing.
func newHandlerForTest(c clientset.Interface) (*podNodeSelector, informers.SharedInformerFactory, error) {
	f := informers.NewSharedInformerFactory(c, 5*time.Minute)
	handler := NewPodNodeSelector(nil)
	pluginInitializer := kubeadmission.NewPluginInitializer(c, nil, f, nil, nil, nil, nil)
	pluginInitializer.Initialize(handler)
	err := admission.Validate(handler)
	return handler, f, err
}
