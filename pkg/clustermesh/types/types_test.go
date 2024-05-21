// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClusterNameValidate(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		check       assert.ErrorAssertionFunc
	}{
		{
			name:        "empty",
			clusterName: "",
			check:       assert.Error,
		},
		{
			name:        "single character",
			clusterName: "a",
			check:       assert.NoError,
		},
		{
			name:        "63 characters",
			clusterName: "abcdefghijklmnopqrstuvwxyz0123456789-abcdefghijklmnopqrstuvwxyz",
			check:       assert.NoError,
		},
		{
			name:        "64 characters",
			clusterName: "abcdefghijklmnopqrstuvwxyz0123456789-abcdefghijklmnopqrstuvwxyz0",
			check:       assert.Error,
		},
		{
			name:        "start and end with lowercase letter",
			clusterName: "az",
			check:       assert.NoError,
		},
		{
			name:        "start and end with number",
			clusterName: "09",
			check:       assert.NoError,
		},
		{
			name:        "start with a dash",
			clusterName: "-a",
			check:       assert.Error,
		},
		{
			name:        "end with a dash",
			clusterName: "0-",
			check:       assert.Error,
		},
		{
			name:        "uppercase letters",
			clusterName: "aBYz",
			check:       assert.Error,
		},
		{
			name:        "invalid characters",
			clusterName: "a^x",
			check:       assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, ValidateClusterName(tt.clusterName))
		})
	}
}
