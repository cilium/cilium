/*
Copyright 2019 The Kubernetes Authors.

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

package markers

// Must panics on errors creating definitions.
func Must(def *Definition, err error) *Definition {
	if err != nil {
		panic(err)
	}
	return def
}

// RegisterAll attempts to register all definitions against the given registry,
// stopping and returning if an error occurs.
func RegisterAll(reg *Registry, defs ...*Definition) error {
	for _, def := range defs {
		if err := reg.Register(def); err != nil {
			return err
		}
	}
	return nil
}
