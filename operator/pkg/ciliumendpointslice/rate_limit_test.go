// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoDynamicRateLimit(t *testing.T) {
	limit := 10.0
	burst := 20
	p := params{
		Logger: log,
		Cfg: Config{
			CESWriteQPSLimit: limit,
			CESWriteQPSBurst: burst,
		},
	}
	config := getRateLimitConfig(p)
	assert.False(t, config.hasDynamicRateLimiting())
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
	assert.False(t, config.updateRateLimiterWithNodes(1000))
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
	assert.False(t, config.updateRateLimiterWithNodes(0))
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
	assert.False(t, config.updateRateLimiterWithNodes(-100))
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
}

func TestSingleDynamicRateLimit(t *testing.T) {
	limit := 15.0
	burst := 30
	p := params{
		Logger: log,
		Cfg: Config{
			CESEnableDynamicRateLimit:   true,
			CESDynamicRateLimitNodes:    []string{"5"},
			CESDynamicRateLimitQPSLimit: []string{strconv.FormatFloat(limit, 'g', -1, 64)},
			CESDynamicRateLimitQPSBurst: []string{strconv.Itoa(burst)},
		},
	}
	config := getRateLimitConfig(p)
	assert.True(t, config.hasDynamicRateLimiting())
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
	assert.False(t, config.updateRateLimiterWithNodes(1000))
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
	assert.False(t, config.updateRateLimiterWithNodes(0))
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
	assert.False(t, config.updateRateLimiterWithNodes(-100))
	assert.Equal(t, limit, config.current.Limit)
	assert.Equal(t, burst, config.current.Burst)
}

func TestMultipleUnsortedDynamicRateLimit(t *testing.T) {
	limit0 := 5.0
	burst0 := 10
	limit1 := 11.0
	burst1 := 22
	limit2 := 16.0
	burst2 := 32
	p := params{
		Logger: log,
		Cfg: Config{
			CESEnableDynamicRateLimit: true,
			CESDynamicRateLimitNodes:  []string{"15", "5", "25"},
			CESDynamicRateLimitQPSLimit: []string{
				strconv.FormatFloat(limit1, 'g', -1, 64),
				strconv.FormatFloat(limit0, 'g', -1, 64),
				strconv.FormatFloat(limit2, 'g', -1, 64),
			},
			CESDynamicRateLimitQPSBurst: []string{
				strconv.Itoa(burst1),
				strconv.Itoa(burst0),
				strconv.Itoa(burst2),
			},
		},
	}
	config := getRateLimitConfig(p)
	assert.True(t, config.hasDynamicRateLimiting())
	assert.Equal(t, limit0, config.current.Limit)
	assert.Equal(t, burst0, config.current.Burst)
	assert.True(t, config.updateRateLimiterWithNodes(1000))
	assert.Equal(t, limit2, config.current.Limit)
	assert.Equal(t, burst2, config.current.Burst)
	assert.True(t, config.updateRateLimiterWithNodes(0))
	assert.Equal(t, limit0, config.current.Limit)
	assert.Equal(t, burst0, config.current.Burst)
	assert.True(t, config.updateRateLimiterWithNodes(24))
	assert.Equal(t, limit1, config.current.Limit)
	assert.Equal(t, burst1, config.current.Burst)
	assert.True(t, config.updateRateLimiterWithNodes(25))
	assert.Equal(t, limit2, config.current.Limit)
	assert.Equal(t, burst2, config.current.Burst)
	assert.True(t, config.updateRateLimiterWithNodes(-100))
	assert.Equal(t, limit0, config.current.Limit)
	assert.Equal(t, burst0, config.current.Burst)
	assert.True(t, config.updateRateLimiterWithNodes(16))
	assert.Equal(t, limit1, config.current.Limit)
	assert.Equal(t, burst1, config.current.Burst)
	assert.False(t, config.updateRateLimiterWithNodes(23))
	assert.Equal(t, limit1, config.current.Limit)
	assert.Equal(t, burst1, config.current.Burst)
}
