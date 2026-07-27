// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package object

import (
	"fmt"
)

// InvalidAnnotationError represents an invalid annotation.
// Fields are exposed to allow callers to perform introspection.
type InvalidAnnotationError struct {
	Annotation string
	Cause      error
}

func (iae InvalidAnnotationError) Error() string {
	return fmt.Sprintf("invalid %q annotation: %v",
		iae.Annotation, iae.Cause)
}

func (iae InvalidAnnotationError) Unwrap() error {
	return iae.Cause
}
