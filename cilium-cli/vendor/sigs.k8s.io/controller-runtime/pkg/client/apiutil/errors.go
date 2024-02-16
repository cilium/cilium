/*
Copyright 2023 The Kubernetes Authors.

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

package apiutil

import (
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ErrResourceDiscoveryFailed is returned if the RESTMapper cannot discover supported resources for some GroupVersions.
// It wraps the errors encountered, except "NotFound" errors are replaced with meta.NoResourceMatchError, for
// backwards compatibility with code that uses meta.IsNoMatchError() to check for unsupported APIs.
type ErrResourceDiscoveryFailed map[schema.GroupVersion]error

// Error implements the error interface.
func (e *ErrResourceDiscoveryFailed) Error() string {
	subErrors := []string{}
	for k, v := range *e {
		subErrors = append(subErrors, fmt.Sprintf("%s: %v", k, v))
	}
	sort.Strings(subErrors)
	return fmt.Sprintf("unable to retrieve the complete list of server APIs: %s", strings.Join(subErrors, ", "))
}

func (e *ErrResourceDiscoveryFailed) Unwrap() []error {
	subErrors := []error{}
	for gv, err := range *e {
		if apierrors.IsNotFound(err) {
			err = &meta.NoResourceMatchError{PartialResource: gv.WithResource("")}
		}
		subErrors = append(subErrors, err)
	}
	return subErrors
}
