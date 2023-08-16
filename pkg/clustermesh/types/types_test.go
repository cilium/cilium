// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCiliumClusterConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *CiliumClusterConfig
		mode      ValidationMode
		assertion func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
	}{
		{
			name:      "Nil config (Backward)",
			cfg:       nil,
			mode:      BackwardCompatible,
			assertion: assert.NoError,
		},
		{
			name:      "Nil config (Strict)",
			cfg:       nil,
			mode:      Strict,
			assertion: assert.Error,
		},
		{
			name:      "Empty config (Backward)",
			cfg:       &CiliumClusterConfig{},
			mode:      BackwardCompatible,
			assertion: assert.NoError,
		},
		{
			name:      "Empty config (Strict)",
			cfg:       &CiliumClusterConfig{},
			mode:      Strict,
			assertion: assert.Error,
		},
		{
			name:      "Valid config (Backward)",
			cfg:       &CiliumClusterConfig{ID: 255},
			mode:      BackwardCompatible,
			assertion: assert.NoError,
		},
		{
			name:      "Valid config (Strict)",
			cfg:       &CiliumClusterConfig{ID: 255},
			mode:      Strict,
			assertion: assert.NoError,
		},
		{
			name:      "Invalid config (Backward)",
			cfg:       &CiliumClusterConfig{ID: 256},
			mode:      BackwardCompatible,
			assertion: assert.Error,
		},
		{
			name:      "Invalid config (Strict)",
			cfg:       &CiliumClusterConfig{ID: 256},
			mode:      Strict,
			assertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.cfg.Validate(tt.mode))
		})
	}
}
