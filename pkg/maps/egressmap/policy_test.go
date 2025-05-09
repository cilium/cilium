// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPolicyMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.NoError(t, rlimit.RemoveMemlock())

	t.Run("IPv4 policies", func(t *testing.T) {
		egressPolicyMap := createPolicyMap4(hivetest.Lifecycle(t), DefaultPolicyConfig, ebpf.PinNone)

		sourceIP1 := netip.MustParseAddr("1.1.1.1")
		sourceIP2 := netip.MustParseAddr("1.1.1.2")

		destCIDR1 := netip.MustParsePrefix("2.2.1.0/24")
		destCIDR2 := netip.MustParsePrefix("2.2.2.0/24")

		egressIP1 := netip.MustParseAddr("3.3.3.1")
		egressIP2 := netip.MustParseAddr("3.3.3.2")

		err := egressPolicyMap.Update(sourceIP1, destCIDR1, egressIP1, egressIP1)
		assert.NoError(t, err)

		err = egressPolicyMap.Update(sourceIP2, destCIDR2, egressIP2, egressIP2)
		assert.NoError(t, err)

		val, err := egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), egressIP1)

		val, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP2)
		assert.Equal(t, val.GatewayIP.Addr(), egressIP2)

		err = egressPolicyMap.Delete(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		val, err = egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), egressIP1)

		_, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	})

	t.Run("IPv6 policies", func(t *testing.T) {
		fmt.Print("HELLO")
		egressPolicyMap := createPolicyMap6(hivetest.Lifecycle(t), DefaultPolicyConfig, ebpf.PinNone)

		sourceIP1 := netip.MustParseAddr("2001:db8:1::1")
		sourceIP2 := netip.MustParseAddr("2001:db8:1::2")

		destCIDR1 := netip.MustParsePrefix("2001:db8:2::/64")
		destCIDR2 := netip.MustParsePrefix("2001:db8:3::/64")

		egressIP1 := netip.MustParseAddr("2001:db8:4::1")
		egressIP2 := netip.MustParseAddr("2001:db8:4::2")

		gatewayIP1 := netip.MustParseAddr("3.3.3.1")
		gatewayIP2 := netip.MustParseAddr("3.3.3.2")

		err := egressPolicyMap.Update(sourceIP1, destCIDR1, egressIP1, gatewayIP1)
		assert.NoError(t, err)

		err = egressPolicyMap.Update(sourceIP2, destCIDR2, egressIP2, gatewayIP2)
		assert.NoError(t, err)

		val, err := egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), gatewayIP1)

		val, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP2)
		assert.Equal(t, val.GatewayIP.Addr(), gatewayIP2)

		err = egressPolicyMap.Delete(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		val, err = egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), gatewayIP1)

		_, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	})
}

// TestMapRaceCondition demonstrates the race condition where a map is closed
// while it's being accessed via DumpReliablyWithCallback.
func TestMapRaceCondition(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.NoError(t, rlimit.RemoveMemlock())

	// Create a map
	egressPolicyMap := createPolicyMap4(hivetest.Lifecycle(t), DefaultPolicyConfig, ebpf.PinNone)

	// Add multiple entries to make the iteration take longer
	for i := 1; i <= 100; i++ {
		sourceIP := netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i%255))
		destCIDR := netip.MustParsePrefix(fmt.Sprintf("2.2.%d.0/24", i%255))
		egressIP := netip.MustParseAddr(fmt.Sprintf("3.3.3.%d", i%255))

		err := egressPolicyMap.Update(sourceIP, destCIDR, egressIP, egressIP)
		assert.NoError(t, err)
	}

	// Create a wait group to synchronize goroutines
	var wg sync.WaitGroup
	wg.Add(2)

	// Signal channel to coordinate the race
	start := make(chan struct{})
	// Channel to signal when iteration has started
	iterationStarted := make(chan struct{}, 1)

	// Goroutine 1: Iterate over the map
	go func() {
		defer wg.Done()
		<-start // Wait for signal to start

		// Use DumpReliablyWithCallback to iterate
		stats := bpf.NewDumpStats(egressPolicyMap.m)
		err := egressPolicyMap.m.DumpReliablyWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
			// Signal that iteration has started
			select {
			case iterationStarted <- struct{}{}:
			default:
			}
			// Sleep to make the race more likely
			time.Sleep(100 * time.Millisecond)
			t.Logf("Found entry: %s -> %s\n", key.String(), value.String())
		}, stats)

		if err != nil {
			t.Logf("Error during map iteration: %v\n", err)
		}
	}()

	// Goroutine 2: Close the map
	go func() {
		defer wg.Done()
		<-start // Wait for signal to start

		// Wait for iteration to start
		<-iterationStarted

		// Close the map while iteration is in progress
		t.Log("Closing map...")
		egressPolicyMap.m.Close()
	}()

	// Start both goroutines
	close(start)

	// Wait for both goroutines to complete
	wg.Wait()

	// Note: This test is expected to fail without the fix from PR #38590
	// With the fix, it should pass without errors
}
