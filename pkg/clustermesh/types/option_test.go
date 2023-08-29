// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClusterInfoValidate(t *testing.T) {
	assert.NoError(t, ClusterInfo{ID: 0, Name: "default"}.Validate())
	assert.NoError(t, ClusterInfo{ID: 0, Name: "foo"}.Validate())
	assert.NoError(t, ClusterInfo{ID: 1, Name: "foo"}.Validate())
	assert.NoError(t, ClusterInfo{ID: 255, Name: "foo"}.Validate())
	assert.Error(t, ClusterInfo{ID: 74, Name: "default"}.Validate())
	assert.Error(t, ClusterInfo{ID: 256, Name: "foo"}.Validate())

	assert.Error(t, ClusterInfo{ID: 0, Name: "default"}.ValidateStrict())
	assert.Error(t, ClusterInfo{ID: 0, Name: "foo"}.ValidateStrict())
	assert.NoError(t, ClusterInfo{ID: 1, Name: "foo"}.ValidateStrict())
	assert.NoError(t, ClusterInfo{ID: 255, Name: "foo"}.ValidateStrict())
	assert.Error(t, ClusterInfo{ID: 74, Name: "default"}.ValidateStrict())
	assert.Error(t, ClusterInfo{ID: 256, Name: "foo"}.ValidateStrict())
}
