// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/defaults"
)

func TestConfigDefaults(t *testing.T) {
	cfg := defaultConfig

	assert.Equal(t, defaults.IPAMPreAllocation, cfg.IPAMPreAllocate)
	assert.Equal(t, defaults.IPAMMinAllocation, cfg.IPAMMinAllocate)
	assert.Equal(t, defaults.IPAMMaxAllocation, cfg.IPAMMaxAllocate)
	assert.Equal(t, defaults.IPAMMaxAboveWatermark, cfg.IPAMMaxAboveWatermark)
}

func TestConfigFlags(t *testing.T) {
	cfg := defaultConfig
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)

	cfg.Flags(flags)

	// Verify that flags are registered
	assert.NotNil(t, flags.Lookup("ipam-pre-allocate"))
	assert.NotNil(t, flags.Lookup("ipam-min-allocate"))
	assert.NotNil(t, flags.Lookup("ipam-max-allocate"))
	assert.NotNil(t, flags.Lookup("ipam-max-above-watermark"))

	// Verify default values
	preAllocateFlag := flags.Lookup("ipam-pre-allocate")
	assert.Equal(t, "8", preAllocateFlag.DefValue)

	minAllocateFlag := flags.Lookup("ipam-min-allocate")
	assert.Equal(t, "0", minAllocateFlag.DefValue)
}
