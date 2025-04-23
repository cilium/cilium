// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package backoff

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestJitter(t *testing.T) {
	var prev time.Duration
	for range 100 {
		current := CalculateDuration(time.Second, time.Minute, 2.0, true, 1)
		require.NotEqual(t, prev, current)
		prev = current
	}
}

type fakeNodeManager struct {
	nodes *int
}

func (f *fakeNodeManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	numNodes := *f.nodes

	if numNodes == 0 {
		return baseInterval
	}

	waitNanoseconds := float64(baseInterval.Nanoseconds()) * math.Log1p(float64(numNodes))
	return time.Duration(int64(waitNanoseconds))
}

func TestNewNodeManager(t *testing.T) {
	mgr := NewNodeManager(func(baseInterval time.Duration) time.Duration { return 2 * baseInterval })
	require.Equal(t, 2*time.Second, mgr.ClusterSizeDependantInterval(1*time.Second))

	mgr = NewNodeManager(nil)
	require.Equal(t, 1*time.Second, mgr.ClusterSizeDependantInterval(1*time.Second))
}

func TestClusterSizeDependantInterval(t *testing.T) {
	var (
		nnodes      = 0
		nodeManager = fakeNodeManager{
			nodes: &nnodes,
		}
	)

	nodeBackoff := &Exponential{
		Logger:      hivetest.Logger(t),
		Min:         time.Second,
		Max:         2 * time.Minute,
		NodeManager: &nodeManager,
		Jitter:      true,
		Factor:      2.0,
	}

	fmt.Printf("nodes      4        16       128       512      1024      2048\n")
	for attempt := 1; attempt <= 8; attempt++ {
		fmt.Printf("%d:", attempt)
		for _, n := range []int{4, 16, 128, 512, 1024, 2048} {
			nnodes = n
			fmt.Printf("%10s", nodeBackoff.Duration(attempt).Round(time.Second/10))
		}
		fmt.Printf("\n")
	}
}

func TestJitterDistribution(t *testing.T) {
	nodeBackoff := &Exponential{
		Logger: hivetest.Logger(t),
		Min:    time.Second,
		Factor: 2.0,
	}

	for attempt := 1; attempt <= 8; attempt++ {
		current := nodeBackoff.Duration(attempt).Round(time.Second / 10)
		fmt.Printf("%d: %s\n", attempt, current)
	}
}
