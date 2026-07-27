/*
Copyright 2025 The Kubernetes Authors.

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

package conversion

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Converter interface {
	ConvertObject(ctx context.Context, src, dst runtime.Object) error
}

type Registry interface {
	RegisterConverter(gk schema.GroupKind, converter Converter) error
	GetConverter(gk schema.GroupKind) (Converter, bool)
}

type registry struct {
	converterByGK map[schema.GroupKind]Converter
}

func NewRegistry() Registry {
	return registry{
		converterByGK: map[schema.GroupKind]Converter{},
	}
}
func (r registry) RegisterConverter(gk schema.GroupKind, converter Converter) error {
	if _, ok := r.converterByGK[gk]; ok {
		return fmt.Errorf("failed to register Converter for GroupKind %s: converter already registered", gk)
	}

	r.converterByGK[gk] = converter
	return nil
}

func (r registry) GetConverter(gk schema.GroupKind) (Converter, bool) {
	c, ok := r.converterByGK[gk]
	return c, ok
}
