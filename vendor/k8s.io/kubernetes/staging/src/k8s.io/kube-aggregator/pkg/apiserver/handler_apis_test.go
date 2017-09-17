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

package apiserver

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/tools/cache"

	"k8s.io/kube-aggregator/pkg/apis/apiregistration"
	listers "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/internalversion"
)

func TestAPIs(t *testing.T) {
	tests := []struct {
		name        string
		apiservices []*apiregistration.APIService
		expected    *metav1.APIGroupList
	}{
		{
			name:        "empty",
			apiservices: []*apiregistration.APIService{},
			expected: &metav1.APIGroupList{
				TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
				Groups: []metav1.APIGroup{
					discoveryGroup,
				},
			},
		},
		{
			name: "simple add",
			apiservices: []*apiregistration.APIService{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.foo"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "foo",
						Version:              "v1",
						GroupPriorityMinimum: 11,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.bar"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "bar",
						Version:              "v1",
						GroupPriorityMinimum: 10,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
			},
			expected: &metav1.APIGroupList{
				TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
				Groups: []metav1.APIGroup{
					discoveryGroup,
					{
						Name: "foo",
						Versions: []metav1.GroupVersionForDiscovery{
							{
								GroupVersion: "foo/v1",
								Version:      "v1",
							},
						},
						PreferredVersion: metav1.GroupVersionForDiscovery{
							GroupVersion: "foo/v1",
							Version:      "v1",
						},
					},
					{
						Name: "bar",
						Versions: []metav1.GroupVersionForDiscovery{
							{
								GroupVersion: "bar/v1",
								Version:      "v1",
							},
						},
						PreferredVersion: metav1.GroupVersionForDiscovery{
							GroupVersion: "bar/v1",
							Version:      "v1",
						},
					},
				},
			},
		},
		{
			name: "sorting",
			apiservices: []*apiregistration.APIService{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.foo"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "foo",
						Version:              "v1",
						GroupPriorityMinimum: 20,
						VersionPriority:      10,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v2.bar"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "bar",
						Version:              "v2",
						GroupPriorityMinimum: 11,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v2.foo"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "foo",
						Version:              "v2",
						GroupPriorityMinimum: 1,
						VersionPriority:      15,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.bar"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "bar",
						Version:              "v1",
						GroupPriorityMinimum: 11,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
			},
			expected: &metav1.APIGroupList{
				TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
				Groups: []metav1.APIGroup{
					discoveryGroup,
					{
						Name: "foo",
						Versions: []metav1.GroupVersionForDiscovery{
							{
								GroupVersion: "foo/v2",
								Version:      "v2",
							},
							{
								GroupVersion: "foo/v1",
								Version:      "v1",
							},
						},
						PreferredVersion: metav1.GroupVersionForDiscovery{
							GroupVersion: "foo/v2",
							Version:      "v2",
						},
					},
					{
						Name: "bar",
						Versions: []metav1.GroupVersionForDiscovery{
							{
								GroupVersion: "bar/v1",
								Version:      "v1",
							},
							{
								GroupVersion: "bar/v2",
								Version:      "v2",
							},
						},
						PreferredVersion: metav1.GroupVersionForDiscovery{
							GroupVersion: "bar/v1",
							Version:      "v1",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		mapper := request.NewRequestContextMapper()
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		handler := &apisHandler{
			codecs: Codecs,
			lister: listers.NewAPIServiceLister(indexer),
			mapper: mapper,
		}
		for _, o := range tc.apiservices {
			indexer.Add(o)
		}

		server := httptest.NewServer(request.WithRequestContext(handler, mapper))
		defer server.Close()

		resp, err := http.Get(server.URL + "/apis")
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		bytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}

		actual := &metav1.APIGroupList{}
		if err := runtime.DecodeInto(Codecs.UniversalDecoder(), bytes, actual); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !apiequality.Semantic.DeepEqual(tc.expected, actual) {
			t.Errorf("%s: %v", tc.name, diff.ObjectDiff(tc.expected, actual))
			continue
		}
	}
}

func TestAPIGroupMissing(t *testing.T) {
	mapper := request.NewRequestContextMapper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	handler := &apiGroupHandler{
		codecs:    Codecs,
		lister:    listers.NewAPIServiceLister(indexer),
		groupName: "groupName",
		delegate: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}),
		contextMapper: mapper,
	}

	server := httptest.NewServer(request.WithRequestContext(handler, mapper))
	defer server.Close()

	// this call should delegate
	resp, err := http.Get(server.URL + "/apis/groupName/foo")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %v, got %v", http.StatusForbidden, resp.StatusCode)
	}

	// groupName still has no api services for it (like it was deleted), it should delegate
	resp, err = http.Get(server.URL + "/apis/groupName/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %v, got %v", http.StatusForbidden, resp.StatusCode)
	}

	// missing group should delegate still has no api services for it (like it was deleted)
	resp, err = http.Get(server.URL + "/apis/missing")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %v, got %v", http.StatusForbidden, resp.StatusCode)
	}
}

func TestAPIGroup(t *testing.T) {
	tests := []struct {
		name        string
		group       string
		apiservices []*apiregistration.APIService
		expected    *metav1.APIGroup
	}{
		{
			name:  "sorting",
			group: "foo",
			apiservices: []*apiregistration.APIService{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.foo"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "foo",
						Version:              "v1",
						GroupPriorityMinimum: 20,
						VersionPriority:      10,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v2.bar"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "bar",
						Version:              "v2",
						GroupPriorityMinimum: 11,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v2.foo"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "foo",
						Version:              "v2",
						GroupPriorityMinimum: 1,
						VersionPriority:      15,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "v1.bar"},
					Spec: apiregistration.APIServiceSpec{
						Service: &apiregistration.ServiceReference{
							Namespace: "ns",
							Name:      "api",
						},
						Group:                "bar",
						Version:              "v1",
						GroupPriorityMinimum: 11,
					},
					Status: apiregistration.APIServiceStatus{
						Conditions: []apiregistration.APIServiceCondition{
							{Type: apiregistration.Available, Status: apiregistration.ConditionTrue},
						},
					},
				},
			},
			expected: &metav1.APIGroup{
				TypeMeta: metav1.TypeMeta{Kind: "APIGroup", APIVersion: "v1"},
				Name:     "foo",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "foo/v2",
						Version:      "v2",
					},
					{
						GroupVersion: "foo/v1",
						Version:      "v1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "foo/v2",
					Version:      "v2",
				},
			},
		},
	}

	for _, tc := range tests {
		mapper := request.NewRequestContextMapper()
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		handler := &apiGroupHandler{
			codecs:        Codecs,
			lister:        listers.NewAPIServiceLister(indexer),
			groupName:     "foo",
			contextMapper: mapper,
		}
		for _, o := range tc.apiservices {
			indexer.Add(o)
		}

		server := httptest.NewServer(request.WithRequestContext(handler, mapper))
		defer server.Close()

		resp, err := http.Get(server.URL + "/apis/" + tc.group)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			response, _ := httputil.DumpResponse(resp, true)
			t.Errorf("%s: %v", tc.name, string(response))
			continue
		}
		bytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}

		actual := &metav1.APIGroup{}
		if err := runtime.DecodeInto(Codecs.UniversalDecoder(), bytes, actual); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !apiequality.Semantic.DeepEqual(tc.expected, actual) {
			t.Errorf("%s: %v", tc.name, diff.ObjectDiff(tc.expected, actual))
			continue
		}
	}
}
