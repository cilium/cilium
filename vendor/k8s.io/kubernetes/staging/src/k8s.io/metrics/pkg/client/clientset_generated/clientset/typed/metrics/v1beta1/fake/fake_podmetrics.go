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

package fake

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
)

// FakePodMetricses implements PodMetricsInterface
type FakePodMetricses struct {
	Fake *FakeMetricsV1beta1
	ns   string
}

var podmetricsesResource = schema.GroupVersionResource{Group: "metrics", Version: "v1beta1", Resource: "pods"}

var podmetricsesKind = schema.GroupVersionKind{Group: "metrics", Version: "v1beta1", Kind: "PodMetrics"}

// Get takes name of the podMetrics, and returns the corresponding podMetrics object, and an error if there is any.
func (c *FakePodMetricses) Get(name string, options v1.GetOptions) (result *v1beta1.PodMetrics, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(podmetricsesResource, c.ns, name), &v1beta1.PodMetrics{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.PodMetrics), err
}

// List takes label and field selectors, and returns the list of PodMetricses that match those selectors.
func (c *FakePodMetricses) List(opts v1.ListOptions) (result *v1beta1.PodMetricsList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(podmetricsesResource, podmetricsesKind, c.ns, opts), &v1beta1.PodMetricsList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.PodMetricsList{}
	for _, item := range obj.(*v1beta1.PodMetricsList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested podMetricses.
func (c *FakePodMetricses) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(podmetricsesResource, c.ns, opts))

}
