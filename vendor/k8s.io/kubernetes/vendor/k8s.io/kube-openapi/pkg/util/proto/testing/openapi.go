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

package testing

import (
	"io/ioutil"
	"os"
	"sync"

	yaml "gopkg.in/yaml.v2"

	"github.com/googleapis/gnostic/OpenAPIv2"
	"github.com/googleapis/gnostic/compiler"
)

// Fake opens and returns a openapi swagger from a file Path. It will
// parse only once and then return the same copy everytime.
type Fake struct {
	Path string

	once     sync.Once
	document *openapi_v2.Document
	err      error
}

// OpenAPISchema returns the openapi document and a potential error.
func (f *Fake) OpenAPISchema() (*openapi_v2.Document, error) {
	f.once.Do(func() {
		_, err := os.Stat(f.Path)
		if err != nil {
			f.err = err
			return
		}
		spec, err := ioutil.ReadFile(f.Path)
		if err != nil {
			f.err = err
			return
		}
		var info yaml.MapSlice
		err = yaml.Unmarshal(spec, &info)
		if err != nil {
			f.err = err
			return
		}
		f.document, f.err = openapi_v2.NewDocument(info, compiler.NewContext("$root", nil))
	})
	return f.document, f.err
}

// FakeClient implements a dummy OpenAPISchemaInterface that uses the
// fake OpenAPI schema given as a parameter, and count the number of
// call to the function.
type FakeClient struct {
	Calls int
	Err   error

	fake *Fake
}

// NewFakeClient creates a new FakeClient from the given Fake.
func NewFakeClient(f *Fake) *FakeClient {
	return &FakeClient{fake: f}
}

// OpenAPISchema returns a OpenAPI Document as returned by the fake, but
// it also counts the number of calls.
func (f *FakeClient) OpenAPISchema() (*openapi_v2.Document, error) {
	f.Calls = f.Calls + 1

	if f.Err != nil {
		return nil, f.Err
	}

	return f.fake.OpenAPISchema()
}
