// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestObjectMetaSetManagedFields(t *testing.T) {
	meta := &ObjectMeta{Name: "foo"}

	// Clearing the entries of an object which has none is a no-op, as relied
	// upon by the normalization of the objects entering the informer stores.
	assert.NotPanics(t, func() { meta.SetManagedFields(nil) })
	assert.Equal(t, &ObjectMeta{Name: "foo"}, meta)

	// Storing entries remains unsupported: the slim ObjectMeta has nowhere to
	// keep them, so silently dropping them would lose data.
	assert.Panics(t, func() {
		meta.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "cilium-agent"}})
	})
	// An empty but non-nil slice is the reset signal of the apiserver, which
	// is likewise not something this type can represent.
	assert.Panics(t, func() { meta.SetManagedFields([]metav1.ManagedFieldsEntry{}) })
}
