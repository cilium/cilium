// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package backoff

import (
	"fmt"
	"math"
	"testing"
	"time"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type BackoffSuite struct{}

var _ = check.Suite(&BackoffSuite{})

func (b *BackoffSuite) TestJitter(c *check.C) {
	var prev time.Duration
	for i := 0; i < 100; i++ {
		current := CalculateDuration(time.Second, time.Minute, 2.0, true, 1)
		c.Assert(current, check.Not(check.Equals), prev)
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

func (b *BackoffSuite) TestClusterSizeDependantInterval(c *check.C) {
	var (
		nnodes      = 0
		nodeManager = fakeNodeManager{
			nodes: &nnodes,
		}
	)

	nodeBackoff := &Exponential{
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

func (b *BackoffSuite) TestJitterDistribution(c *check.C) {
	nodeBackoff := &Exponential{
		Min:    time.Second,
		Factor: 2.0,
	}

	for attempt := 1; attempt <= 8; attempt++ {
		current := nodeBackoff.Duration(attempt).Round(time.Second / 10)
		fmt.Printf("%d: %s\n", attempt, current)
	}
}
