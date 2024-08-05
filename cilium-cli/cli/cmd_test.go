// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/cilium-cli/api"
)

const usage = "override usage"

type testHooks struct {
	api.NopHooks
}

func (th *testHooks) InitializeCommand(rootCmd *cobra.Command) {
	rootCmd.Use = usage
}

func TestInitializeCommandHook(t *testing.T) {
	cmd := NewCiliumCommand(&testHooks{})
	assert.Equal(t, usage, cmd.Use)
}
