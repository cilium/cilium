// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func Test_normalizeFlags(t *testing.T) {
	cmd := newCmdInstallWithHelm()
	assert.Equal(t, pflag.NormalizedName("set"), normalizeFlags(cmd.Flags(), "helm-set"))
	assert.Equal(t, pflag.NormalizedName("set-file"), normalizeFlags(cmd.Flags(), "helm-set-file"))
	assert.Equal(t, pflag.NormalizedName("set-string"), normalizeFlags(cmd.Flags(), "helm-set-string"))
	assert.Equal(t, pflag.NormalizedName("values"), normalizeFlags(cmd.Flags(), "helm-values"))
}
