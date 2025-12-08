package policymap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

// TestArenaFlagLogic verifies that EnablePolicySharedMapArena flag influences the creation logic.
func TestArenaFlagLogic(t *testing.T) {
	t.Cleanup(func() {
		option.Config.PolicyRuleListNodesMax = 100
	})

	// Case 1: Flag False
	option.Config.EnablePolicySharedMapArena = false
	resetSharedManagerForTest()
	mgr := getSharedManager()

	assert.Nil(t, mgr.allocator.arenaAlloc, "Arena Allocator should be nil when flag is false")

	// Case 2: Flag True (But Map Missing)
	option.Config.EnablePolicySharedMapArena = true

	resetSharedManagerForTest()
	mgr2 := getSharedManager()

	assert.Nil(t, mgr2.allocator.arenaAlloc, "Arena Allocator should be nil if map is missing")
}

func TestSharedManagerEnabled_Arena(t *testing.T) {
	t.Cleanup(func() {
		option.Config.EnablePolicySharedMapArena = false
	})

	// Case 1: All disabled
	option.Config.EnablePolicySharedMapArena = false
	assert.False(t, SharedManagerEnabled())

	// Case 2: Only Arena Enabled -> Should be True
	option.Config.EnablePolicySharedMapArena = true
	assert.True(t, SharedManagerEnabled(), "SharedManager should be enabled if Arena is enabled")
}
