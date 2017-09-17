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

package cmd

import (
	"bytes"
	"net/http"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/rest/fake"
	"k8s.io/kubernetes/pkg/api"
	cmdtesting "k8s.io/kubernetes/pkg/kubectl/cmd/testing"
)

func TestValidateAnnotationOverwrites(t *testing.T) {
	tests := []struct {
		meta        *metav1.ObjectMeta
		annotations map[string]string
		expectErr   bool
		scenario    string
	}{
		{
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					"a": "A",
					"b": "B",
				},
			},
			annotations: map[string]string{
				"a": "a",
				"c": "C",
			},
			scenario:  "share first annotation",
			expectErr: true,
		},
		{
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					"a": "A",
					"c": "C",
				},
			},
			annotations: map[string]string{
				"b": "B",
				"c": "c",
			},
			scenario:  "share second annotation",
			expectErr: true,
		},
		{
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					"a": "A",
					"c": "C",
				},
			},
			annotations: map[string]string{
				"b": "B",
				"d": "D",
			},
			scenario: "no overlap",
		},
		{
			meta: &metav1.ObjectMeta{},
			annotations: map[string]string{
				"a": "A",
				"b": "B",
			},
			scenario: "no annotations",
		},
	}
	for _, test := range tests {
		err := validateNoAnnotationOverwrites(test.meta, test.annotations)
		if test.expectErr && err == nil {
			t.Errorf("%s: unexpected non-error", test.scenario)
		} else if !test.expectErr && err != nil {
			t.Errorf("%s: unexpected error: %v", test.scenario, err)
		}
	}
}

func TestParseAnnotations(t *testing.T) {
	testURL := "https://test.com/index.htm?id=123#u=user-name"
	testJSON := `'{"kind":"SerializedReference","apiVersion":"v1","reference":{"kind":"ReplicationController","namespace":"default","name":"my-nginx","uid":"c544ee78-2665-11e5-8051-42010af0c213","apiVersion":"v1","resourceVersion":"61368"}}'`
	tests := []struct {
		annotations    []string
		expected       map[string]string
		expectedRemove []string
		scenario       string
		expectedErr    string
		expectErr      bool
	}{
		{
			annotations:    []string{"a=b", "c=d"},
			expected:       map[string]string{"a": "b", "c": "d"},
			expectedRemove: []string{},
			scenario:       "add two annotations",
			expectErr:      false,
		},
		{
			annotations:    []string{"url=" + testURL, api.CreatedByAnnotation + "=" + testJSON},
			expected:       map[string]string{"url": testURL, api.CreatedByAnnotation: testJSON},
			expectedRemove: []string{},
			scenario:       "add annotations with special characters",
			expectErr:      false,
		},
		{
			annotations:    []string{},
			expected:       map[string]string{},
			expectedRemove: []string{},
			scenario:       "add no annotations",
			expectErr:      false,
		},
		{
			annotations:    []string{"a=b", "c=d", "e-"},
			expected:       map[string]string{"a": "b", "c": "d"},
			expectedRemove: []string{"e"},
			scenario:       "add two annotations, remove one",
			expectErr:      false,
		},
		{
			annotations: []string{"ab", "c=d"},
			expectedErr: "invalid annotation format: ab",
			scenario:    "incorrect annotation input (missing =value)",
			expectErr:   true,
		},
		{
			annotations:    []string{"a="},
			expected:       map[string]string{"a": ""},
			expectedRemove: []string{},
			scenario:       "add valid annotation with empty value",
			expectErr:      false,
		},
		{
			annotations: []string{"ab", "a="},
			expectedErr: "invalid annotation format: ab",
			scenario:    "incorrect annotation input (missing =value)",
			expectErr:   true,
		},
		{
			annotations: []string{"-"},
			expectedErr: "invalid annotation format: -",
			scenario:    "incorrect annotation input (missing key)",
			expectErr:   true,
		},
		{
			annotations: []string{"=bar"},
			expectedErr: "invalid annotation format: =bar",
			scenario:    "incorrect annotation input (missing key)",
			expectErr:   true,
		},
	}
	for _, test := range tests {
		annotations, remove, err := parseAnnotations(test.annotations)
		switch {
		case test.expectErr && err == nil:
			t.Errorf("%s: unexpected non-error, should return %v", test.scenario, test.expectedErr)
		case test.expectErr && err.Error() != test.expectedErr:
			t.Errorf("%s: unexpected error %v, expected %v", test.scenario, err, test.expectedErr)
		case !test.expectErr && err != nil:
			t.Errorf("%s: unexpected error %v", test.scenario, err)
		case !test.expectErr && !reflect.DeepEqual(annotations, test.expected):
			t.Errorf("%s: expected %v, got %v", test.scenario, test.expected, annotations)
		case !test.expectErr && !reflect.DeepEqual(remove, test.expectedRemove):
			t.Errorf("%s: expected %v, got %v", test.scenario, test.expectedRemove, remove)
		}
	}
}

func TestValidateAnnotations(t *testing.T) {
	tests := []struct {
		removeAnnotations []string
		newAnnotations    map[string]string
		expectedErr       string
		scenario          string
	}{
		{
			expectedErr:       "can not both modify and remove the following annotation(s) in the same command: a",
			removeAnnotations: []string{"a"},
			newAnnotations:    map[string]string{"a": "b", "c": "d"},
			scenario:          "remove an added annotation",
		},
		{
			expectedErr:       "can not both modify and remove the following annotation(s) in the same command: a, c",
			removeAnnotations: []string{"a", "c"},
			newAnnotations:    map[string]string{"a": "b", "c": "d"},
			scenario:          "remove added annotations",
		},
	}
	for _, test := range tests {
		if err := validateAnnotations(test.removeAnnotations, test.newAnnotations); err == nil {
			t.Errorf("%s: unexpected non-error", test.scenario)
		} else if err.Error() != test.expectedErr {
			t.Errorf("%s: expected error %s, got %s", test.scenario, test.expectedErr, err.Error())
		}
	}
}

func TestUpdateAnnotations(t *testing.T) {
	tests := []struct {
		obj         runtime.Object
		overwrite   bool
		version     string
		annotations map[string]string
		remove      []string
		expected    runtime.Object
		expectErr   bool
	}{
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b"},
				},
			},
			annotations: map[string]string{"a": "b"},
			expectErr:   true,
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b"},
				},
			},
			annotations: map[string]string{"a": "c"},
			overwrite:   true,
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "c"},
				},
			},
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b"},
				},
			},
			annotations: map[string]string{"c": "d"},
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b", "c": "d"},
				},
			},
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b"},
				},
			},
			annotations: map[string]string{"c": "d"},
			version:     "2",
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations:     map[string]string{"a": "b", "c": "d"},
					ResourceVersion: "2",
				},
			},
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b"},
				},
			},
			annotations: map[string]string{},
			remove:      []string{"a"},
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b", "c": "d"},
				},
			},
			annotations: map[string]string{"e": "f"},
			remove:      []string{"a"},
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"c": "d",
						"e": "f",
					},
				},
			},
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b", "c": "d"},
				},
			},
			annotations: map[string]string{"e": "f"},
			remove:      []string{"g"},
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"a": "b",
						"c": "d",
						"e": "f",
					},
				},
			},
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b", "c": "d"},
				},
			},
			remove: []string{"e"},
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"a": "b",
						"c": "d",
					},
				},
			},
		},
		{
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{},
			},
			annotations: map[string]string{"a": "b"},
			expected: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"a": "b"},
				},
			},
		},
	}
	for _, test := range tests {
		options := &AnnotateOptions{
			overwrite:         test.overwrite,
			newAnnotations:    test.annotations,
			removeAnnotations: test.remove,
			resourceVersion:   test.version,
		}
		err := options.updateAnnotations(test.obj)
		if test.expectErr {
			if err == nil {
				t.Errorf("unexpected non-error: %v", test)
			}
			continue
		}
		if !test.expectErr && err != nil {
			t.Errorf("unexpected error: %v %v", err, test)
		}
		if !reflect.DeepEqual(test.obj, test.expected) {
			t.Errorf("expected: %v, got %v", test.expected, test.obj)
		}
	}
}

func TestAnnotateErrors(t *testing.T) {
	testCases := map[string]struct {
		args  []string
		flags map[string]string
		errFn func(error) bool
	}{
		"no args": {
			args:  []string{},
			errFn: func(err error) bool { return strings.Contains(err.Error(), "one or more resources must be specified") },
		},
		"not enough annotations": {
			args: []string{"pods"},
			errFn: func(err error) bool {
				return strings.Contains(err.Error(), "at least one annotation update is required")
			},
		},
		"wrong annotations": {
			args: []string{"pods", "-"},
			errFn: func(err error) bool {
				return strings.Contains(err.Error(), "at least one annotation update is required")
			},
		},
		"wrong annotations 2": {
			args: []string{"pods", "=bar"},
			errFn: func(err error) bool {
				return strings.Contains(err.Error(), "at least one annotation update is required")
			},
		},
		"no resources remove annotations": {
			args:  []string{"pods-"},
			errFn: func(err error) bool { return strings.Contains(err.Error(), "one or more resources must be specified") },
		},
		"no resources add annotations": {
			args:  []string{"pods=bar"},
			errFn: func(err error) bool { return strings.Contains(err.Error(), "one or more resources must be specified") },
		},
	}

	for k, testCase := range testCases {
		f, tf, _, _ := cmdtesting.NewAPIFactory()
		tf.Printer = &testPrinter{}
		tf.Namespace = "test"
		tf.ClientConfig = &restclient.Config{ContentConfig: restclient.ContentConfig{GroupVersion: &api.Registry.GroupOrDie(api.GroupName).GroupVersion}}

		buf := bytes.NewBuffer([]byte{})
		cmd := NewCmdAnnotate(f, buf)
		cmd.SetOutput(buf)

		for k, v := range testCase.flags {
			cmd.Flags().Set(k, v)
		}
		options := &AnnotateOptions{}
		err := options.Complete(buf, cmd, testCase.args)
		if err == nil {
			err = options.Validate()
		}
		if !testCase.errFn(err) {
			t.Errorf("%s: unexpected error: %v", k, err)
			continue
		}
		if tf.Printer.(*testPrinter).Objects != nil {
			t.Errorf("unexpected print to default printer")
		}
		if buf.Len() > 0 {
			t.Errorf("buffer should be empty: %s", string(buf.Bytes()))
		}
	}
}

func TestAnnotateObject(t *testing.T) {
	pods, _, _ := testData()

	f, tf, codec, _ := cmdtesting.NewAPIFactory()
	tf.Printer = &testPrinter{}
	tf.UnstructuredClient = &fake.RESTClient{
		APIRegistry:          api.Registry,
		NegotiatedSerializer: unstructuredSerializer,
		Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			switch req.Method {
			case "GET":
				switch req.URL.Path {
				case "/namespaces/test/pods/foo":
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: objBody(codec, &pods.Items[0])}, nil
				default:
					t.Fatalf("unexpected request: %#v\n%#v", req.URL, req)
					return nil, nil
				}
			case "PATCH":
				switch req.URL.Path {
				case "/namespaces/test/pods/foo":
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: objBody(codec, &pods.Items[0])}, nil
				default:
					t.Fatalf("unexpected request: %#v\n%#v", req.URL, req)
					return nil, nil
				}
			default:
				t.Fatalf("unexpected request: %s %#v\n%#v", req.Method, req.URL, req)
				return nil, nil
			}
		}),
	}
	tf.Namespace = "test"
	tf.ClientConfig = &restclient.Config{ContentConfig: restclient.ContentConfig{GroupVersion: &api.Registry.GroupOrDie(api.GroupName).GroupVersion}}

	buf := bytes.NewBuffer([]byte{})
	cmd := NewCmdAnnotate(f, buf)
	cmd.SetOutput(buf)
	options := &AnnotateOptions{}
	args := []string{"pods/foo", "a=b", "c-"}
	if err := options.Complete(buf, cmd, args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.RunAnnotate(f, cmd); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnnotateObjectFromFile(t *testing.T) {
	pods, _, _ := testData()

	f, tf, codec, _ := cmdtesting.NewAPIFactory()
	tf.Printer = &testPrinter{}
	tf.UnstructuredClient = &fake.RESTClient{
		APIRegistry:          api.Registry,
		NegotiatedSerializer: unstructuredSerializer,
		Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			switch req.Method {
			case "GET":
				switch req.URL.Path {
				case "/namespaces/test/replicationcontrollers/cassandra":
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: objBody(codec, &pods.Items[0])}, nil
				default:
					t.Fatalf("unexpected request: %#v\n%#v", req.URL, req)
					return nil, nil
				}
			case "PATCH":
				switch req.URL.Path {
				case "/namespaces/test/replicationcontrollers/cassandra":
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: objBody(codec, &pods.Items[0])}, nil
				default:
					t.Fatalf("unexpected request: %#v\n%#v", req.URL, req)
					return nil, nil
				}
			default:
				t.Fatalf("unexpected request: %s %#v\n%#v", req.Method, req.URL, req)
				return nil, nil
			}
		}),
	}
	tf.Namespace = "test"
	tf.ClientConfig = &restclient.Config{ContentConfig: restclient.ContentConfig{GroupVersion: &api.Registry.GroupOrDie(api.GroupName).GroupVersion}}

	buf := bytes.NewBuffer([]byte{})
	cmd := NewCmdAnnotate(f, buf)
	cmd.SetOutput(buf)
	options := &AnnotateOptions{}
	options.Filenames = []string{"../../../examples/storage/cassandra/cassandra-controller.yaml"}
	args := []string{"a=b", "c-"}
	if err := options.Complete(buf, cmd, args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.RunAnnotate(f, cmd); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnnotateLocal(t *testing.T) {
	f, tf, _, _ := cmdtesting.NewAPIFactory()
	tf.UnstructuredClient = &fake.RESTClient{
		APIRegistry:          api.Registry,
		NegotiatedSerializer: unstructuredSerializer,
		Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("unexpected request: %s %#v\n%#v", req.Method, req.URL, req)
			return nil, nil
		}),
	}
	tf.Namespace = "test"
	tf.ClientConfig = &restclient.Config{ContentConfig: restclient.ContentConfig{GroupVersion: &api.Registry.GroupOrDie(api.GroupName).GroupVersion}}

	buf := bytes.NewBuffer([]byte{})
	cmd := NewCmdAnnotate(f, buf)
	cmd.Flags().Set("local", "true")
	options := &AnnotateOptions{}
	options.Filenames = []string{"../../../examples/storage/cassandra/cassandra-controller.yaml"}
	args := []string{"a=b"}
	if err := options.Complete(buf, cmd, args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.RunAnnotate(f, cmd); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnnotateMultipleObjects(t *testing.T) {
	pods, _, _ := testData()

	f, tf, codec, _ := cmdtesting.NewAPIFactory()
	tf.Printer = &testPrinter{}
	tf.UnstructuredClient = &fake.RESTClient{
		APIRegistry:          api.Registry,
		NegotiatedSerializer: unstructuredSerializer,
		Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			switch req.Method {
			case "GET":
				switch req.URL.Path {
				case "/namespaces/test/pods":
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: objBody(codec, pods)}, nil
				default:
					t.Fatalf("unexpected request: %#v\n%#v", req.URL, req)
					return nil, nil
				}
			case "PATCH":
				switch req.URL.Path {
				case "/namespaces/test/pods/foo":
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: objBody(codec, &pods.Items[0])}, nil
				case "/namespaces/test/pods/bar":
					return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: objBody(codec, &pods.Items[1])}, nil
				default:
					t.Fatalf("unexpected request: %#v\n%#v", req.URL, req)
					return nil, nil
				}
			default:
				t.Fatalf("unexpected request: %s %#v\n%#v", req.Method, req.URL, req)
				return nil, nil
			}
		}),
	}
	tf.Namespace = "test"
	tf.ClientConfig = &restclient.Config{ContentConfig: restclient.ContentConfig{GroupVersion: &api.Registry.GroupOrDie(api.GroupName).GroupVersion}}

	buf := bytes.NewBuffer([]byte{})
	cmd := NewCmdAnnotate(f, buf)
	cmd.SetOutput(buf)
	cmd.Flags().Set("all", "true")
	options := &AnnotateOptions{}
	args := []string{"pods", "a=b", "c-"}
	if err := options.Complete(buf, cmd, args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := options.RunAnnotate(f, cmd); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
