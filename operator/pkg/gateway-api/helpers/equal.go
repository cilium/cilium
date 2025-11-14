// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ObjectsEqual checks to see if two Kubernetes objects are the same object
// (meaning same Kind, Namespace, Name, and Generation). Returns true if all of
// those are the same.
//
// Kind, Namespace, and Name being the same means that they are the same object
// but if the Generation is different, then there has been an update to the object
// between when the two objects were fetched, so any reconciliation should be retried.
// In this case, returns true but an error, so that we can catch this and fail the
// reconciliation.
func ObjectsEqual(a, b client.Object) (bool, error) {
	if a.GetObjectKind().GroupVersionKind() == b.GetObjectKind().GroupVersionKind() &&
		a.GetName() == b.GetName() &&
		a.GetNamespace() == b.GetNamespace() {
		// Same object, need to check generation.

		if a.GetGeneration() == b.GetGeneration() {
			// If generations are the same, then the objects are equal
			return true, nil
		}

		return true, errors.New("Same object, different generations, retry reconciliation")
	}

	return false, nil
}
