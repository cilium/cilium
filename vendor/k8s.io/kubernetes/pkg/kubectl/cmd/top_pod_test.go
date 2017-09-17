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

package cmd

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"net/url"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest/fake"
	"k8s.io/kubernetes/pkg/api"
	cmdtesting "k8s.io/kubernetes/pkg/kubectl/cmd/testing"
	metricsapi "k8s.io/metrics/pkg/apis/metrics/v1alpha1"
)

const (
	topPathPrefix = baseMetricsAddress + "/" + metricsApiVersion
)

func TestTopPod(t *testing.T) {
	testNS := "testns"
	testCases := []struct {
		name            string
		namespace       string
		flags           map[string]string
		args            []string
		expectedPath    string
		expectedQuery   string
		namespaces      []string
		containers      bool
		listsNamespaces bool
	}{
		{
			name:            "all namespaces",
			flags:           map[string]string{"all-namespaces": "true"},
			expectedPath:    topPathPrefix + "/pods",
			namespaces:      []string{testNS, "secondtestns", "thirdtestns"},
			listsNamespaces: true,
		},
		{
			name:         "all in namespace",
			expectedPath: topPathPrefix + "/namespaces/" + testNS + "/pods",
			namespaces:   []string{testNS, testNS},
		},
		{
			name:         "pod with name",
			args:         []string{"pod1"},
			expectedPath: topPathPrefix + "/namespaces/" + testNS + "/pods/pod1",
			namespaces:   []string{testNS},
		},
		{
			name:          "pod with label selector",
			flags:         map[string]string{"selector": "key=value"},
			expectedPath:  topPathPrefix + "/namespaces/" + testNS + "/pods",
			expectedQuery: "labelSelector=" + url.QueryEscape("key=value"),
			namespaces:    []string{testNS, testNS},
		},
		{
			name:         "pod with container metrics",
			flags:        map[string]string{"containers": "true"},
			args:         []string{"pod1"},
			expectedPath: topPathPrefix + "/namespaces/" + testNS + "/pods/pod1",
			namespaces:   []string{testNS},
			containers:   true,
		},
	}
	initTestErrorHandler(t)
	for _, testCase := range testCases {
		t.Logf("Running test case: %s", testCase.name)
		metricsList := testPodMetricsData()
		var expectedMetrics []metricsapi.PodMetrics
		var expectedContainerNames, nonExpectedMetricsNames []string
		for n, m := range metricsList {
			if n < len(testCase.namespaces) {
				m.Namespace = testCase.namespaces[n]
				expectedMetrics = append(expectedMetrics, m)
				for _, c := range m.Containers {
					expectedContainerNames = append(expectedContainerNames, c.Name)
				}
			} else {
				nonExpectedMetricsNames = append(nonExpectedMetricsNames, m.Name)
			}
		}

		var response interface{}
		if len(expectedMetrics) == 1 {
			response = expectedMetrics[0]
		} else {
			response = metricsapi.PodMetricsList{
				ListMeta: metav1.ListMeta{
					ResourceVersion: "2",
				},
				Items: expectedMetrics,
			}
		}

		f, tf, _, ns := cmdtesting.NewAPIFactory()
		tf.Printer = &testPrinter{}
		tf.Client = &fake.RESTClient{
			APIRegistry:          api.Registry,
			NegotiatedSerializer: ns,
			Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch p, m, q := req.URL.Path, req.Method, req.URL.RawQuery; {
				case p == testCase.expectedPath && m == "GET" && (testCase.expectedQuery == "" || q == testCase.expectedQuery):
					body, err := marshallBody(response)
					if err != nil {
						t.Errorf("%s: unexpected error: %v", testCase.name, err)
					}
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: body}, nil
				default:
					t.Fatalf("%s: unexpected request: %#v\nGot URL: %#v\nExpected path: %#v\nExpected query: %#v",
						testCase.name, req, req.URL, testCase.expectedPath, testCase.expectedQuery)
					return nil, nil
				}
			}),
		}
		tf.Namespace = testNS
		tf.ClientConfig = defaultClientConfig()
		buf := bytes.NewBuffer([]byte{})

		cmd := NewCmdTopPod(f, nil, buf)
		for name, value := range testCase.flags {
			cmd.Flags().Set(name, value)
		}
		cmd.Run(cmd, testCase.args)

		// Check the presence of pod names&namespaces/container names in the output.
		result := buf.String()
		if testCase.containers {
			for _, containerName := range expectedContainerNames {
				if !strings.Contains(result, containerName) {
					t.Errorf("%s: missing metrics for container %s: \n%s", testCase.name, containerName, result)
				}
			}
		}
		for _, m := range expectedMetrics {
			if !strings.Contains(result, m.Name) {
				t.Errorf("%s: missing metrics for %s: \n%s", testCase.name, m.Name, result)
			}
			if testCase.listsNamespaces && !strings.Contains(result, m.Namespace) {
				t.Errorf("%s: missing metrics for %s/%s: \n%s", testCase.name, m.Namespace, m.Name, result)
			}
		}
		for _, name := range nonExpectedMetricsNames {
			if strings.Contains(result, name) {
				t.Errorf("%s: unexpected metrics for %s: \n%s", testCase.name, name, result)
			}
		}
	}
}

func TestTopPodCustomDefaults(t *testing.T) {
	customBaseHeapsterServiceAddress := "/api/v1/namespaces/custom-namespace/services/https:custom-heapster-service:/proxy"
	customBaseMetricsAddress := customBaseHeapsterServiceAddress + "/apis/metrics"
	customTopPathPrefix := customBaseMetricsAddress + "/" + metricsApiVersion

	testNS := "custom-namespace"
	testCases := []struct {
		name            string
		namespace       string
		flags           map[string]string
		args            []string
		expectedPath    string
		expectedQuery   string
		namespaces      []string
		containers      bool
		listsNamespaces bool
	}{
		{
			name:            "all namespaces",
			flags:           map[string]string{"all-namespaces": "true"},
			expectedPath:    customTopPathPrefix + "/pods",
			namespaces:      []string{testNS, "secondtestns", "thirdtestns"},
			listsNamespaces: true,
		},
		{
			name:         "all in namespace",
			expectedPath: customTopPathPrefix + "/namespaces/" + testNS + "/pods",
			namespaces:   []string{testNS, testNS},
		},
		{
			name:         "pod with name",
			args:         []string{"pod1"},
			expectedPath: customTopPathPrefix + "/namespaces/" + testNS + "/pods/pod1",
			namespaces:   []string{testNS},
		},
		{
			name:          "pod with label selector",
			flags:         map[string]string{"selector": "key=value"},
			expectedPath:  customTopPathPrefix + "/namespaces/" + testNS + "/pods",
			expectedQuery: "labelSelector=" + url.QueryEscape("key=value"),
			namespaces:    []string{testNS, testNS},
		},
		{
			name:         "pod with container metrics",
			flags:        map[string]string{"containers": "true"},
			args:         []string{"pod1"},
			expectedPath: customTopPathPrefix + "/namespaces/" + testNS + "/pods/pod1",
			namespaces:   []string{testNS},
			containers:   true,
		},
	}
	initTestErrorHandler(t)
	for _, testCase := range testCases {
		t.Logf("Running test case: %s", testCase.name)
		metricsList := testPodMetricsData()
		var expectedMetrics []metricsapi.PodMetrics
		var expectedContainerNames, nonExpectedMetricsNames []string
		for n, m := range metricsList {
			if n < len(testCase.namespaces) {
				m.Namespace = testCase.namespaces[n]
				expectedMetrics = append(expectedMetrics, m)
				for _, c := range m.Containers {
					expectedContainerNames = append(expectedContainerNames, c.Name)
				}
			} else {
				nonExpectedMetricsNames = append(nonExpectedMetricsNames, m.Name)
			}
		}

		var response interface{}
		if len(expectedMetrics) == 1 {
			response = expectedMetrics[0]
		} else {
			response = metricsapi.PodMetricsList{
				ListMeta: metav1.ListMeta{
					ResourceVersion: "2",
				},
				Items: expectedMetrics,
			}
		}

		f, tf, _, ns := cmdtesting.NewAPIFactory()
		tf.Printer = &testPrinter{}
		tf.Client = &fake.RESTClient{
			APIRegistry:          api.Registry,
			NegotiatedSerializer: ns,
			Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch p, m, q := req.URL.Path, req.Method, req.URL.RawQuery; {
				case p == testCase.expectedPath && m == "GET" && (testCase.expectedQuery == "" || q == testCase.expectedQuery):
					body, err := marshallBody(response)
					if err != nil {
						t.Errorf("%s: unexpected error: %v", testCase.name, err)
					}
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: body}, nil
				default:
					t.Fatalf("%s: unexpected request: %#v\nGot URL: %#v\nExpected path: %#v\nExpected query: %#v",
						testCase.name, req, req.URL, testCase.expectedPath, testCase.expectedQuery)
					return nil, nil
				}
			}),
		}
		tf.Namespace = testNS
		tf.ClientConfig = defaultClientConfig()
		buf := bytes.NewBuffer([]byte{})

		opts := &TopPodOptions{
			HeapsterOptions: HeapsterTopOptions{
				Namespace: "custom-namespace",
				Scheme:    "https",
				Service:   "custom-heapster-service",
			},
		}
		cmd := NewCmdTopPod(f, opts, buf)
		for name, value := range testCase.flags {
			cmd.Flags().Set(name, value)
		}
		cmd.Run(cmd, testCase.args)

		// Check the presence of pod names&namespaces/container names in the output.
		result := buf.String()
		if testCase.containers {
			for _, containerName := range expectedContainerNames {
				if !strings.Contains(result, containerName) {
					t.Errorf("%s: missing metrics for container %s: \n%s", testCase.name, containerName, result)
				}
			}
		}
		for _, m := range expectedMetrics {
			if !strings.Contains(result, m.Name) {
				t.Errorf("%s: missing metrics for %s: \n%s", testCase.name, m.Name, result)
			}
			if testCase.listsNamespaces && !strings.Contains(result, m.Namespace) {
				t.Errorf("%s: missing metrics for %s/%s: \n%s", testCase.name, m.Namespace, m.Name, result)
			}
		}
		for _, name := range nonExpectedMetricsNames {
			if strings.Contains(result, name) {
				t.Errorf("%s: unexpected metrics for %s: \n%s", testCase.name, name, result)
			}
		}
	}
}

func testPodMetricsData() []metricsapi.PodMetrics {
	return []metricsapi.PodMetrics{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test", ResourceVersion: "10"},
			Window:     metav1.Duration{Duration: time.Minute},
			Containers: []metricsapi.ContainerMetrics{
				{
					Name: "container1-1",
					Usage: v1.ResourceList{
						v1.ResourceCPU:     *resource.NewMilliQuantity(1, resource.DecimalSI),
						v1.ResourceMemory:  *resource.NewQuantity(2*(1024*1024), resource.DecimalSI),
						v1.ResourceStorage: *resource.NewQuantity(3*(1024*1024), resource.DecimalSI),
					},
				},
				{
					Name: "container1-2",
					Usage: v1.ResourceList{
						v1.ResourceCPU:     *resource.NewMilliQuantity(4, resource.DecimalSI),
						v1.ResourceMemory:  *resource.NewQuantity(5*(1024*1024), resource.DecimalSI),
						v1.ResourceStorage: *resource.NewQuantity(6*(1024*1024), resource.DecimalSI),
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "test", ResourceVersion: "11"},
			Window:     metav1.Duration{Duration: time.Minute},
			Containers: []metricsapi.ContainerMetrics{
				{
					Name: "container2-1",
					Usage: v1.ResourceList{
						v1.ResourceCPU:     *resource.NewMilliQuantity(7, resource.DecimalSI),
						v1.ResourceMemory:  *resource.NewQuantity(8*(1024*1024), resource.DecimalSI),
						v1.ResourceStorage: *resource.NewQuantity(9*(1024*1024), resource.DecimalSI),
					},
				},
				{
					Name: "container2-2",
					Usage: v1.ResourceList{
						v1.ResourceCPU:     *resource.NewMilliQuantity(10, resource.DecimalSI),
						v1.ResourceMemory:  *resource.NewQuantity(11*(1024*1024), resource.DecimalSI),
						v1.ResourceStorage: *resource.NewQuantity(12*(1024*1024), resource.DecimalSI),
					},
				},
				{
					Name: "container2-3",
					Usage: v1.ResourceList{
						v1.ResourceCPU:     *resource.NewMilliQuantity(13, resource.DecimalSI),
						v1.ResourceMemory:  *resource.NewQuantity(14*(1024*1024), resource.DecimalSI),
						v1.ResourceStorage: *resource.NewQuantity(15*(1024*1024), resource.DecimalSI),
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod3", Namespace: "test", ResourceVersion: "12"},
			Window:     metav1.Duration{Duration: time.Minute},
			Containers: []metricsapi.ContainerMetrics{
				{
					Name: "container3-1",
					Usage: v1.ResourceList{
						v1.ResourceCPU:     *resource.NewMilliQuantity(7, resource.DecimalSI),
						v1.ResourceMemory:  *resource.NewQuantity(8*(1024*1024), resource.DecimalSI),
						v1.ResourceStorage: *resource.NewQuantity(9*(1024*1024), resource.DecimalSI),
					},
				},
			},
		},
	}
}
