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

package fake

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"sigs.k8s.io/structured-merge-diff/v6/typed"
)

type multiTypeConverter struct {
	upstream []managedfields.TypeConverter
}

func (m multiTypeConverter) ObjectToTyped(r runtime.Object, o ...typed.ValidationOptions) (*typed.TypedValue, error) {
	var errs []error
	for _, u := range m.upstream {
		res, err := u.ObjectToTyped(r, o...)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return res, nil
	}

	return nil, fmt.Errorf("failed to convert Object to TypedValue: %w", kerrors.NewAggregate(errs))
}

func (m multiTypeConverter) TypedToObject(v *typed.TypedValue) (runtime.Object, error) {
	var errs []error
	for _, u := range m.upstream {
		res, err := u.TypedToObject(v)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return res, nil
	}

	return nil, fmt.Errorf("failed to convert TypedValue to Object: %w", kerrors.NewAggregate(errs))
}
