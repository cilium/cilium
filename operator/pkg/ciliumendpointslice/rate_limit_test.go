// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"encoding/json"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
)

func Test_parseDynamicRateLimitConfig(t *testing.T) {
	jsonCfg := "[{\"nodes\":1,\"limit\":100,\"burst\":200}]"
	wantCfg := rateLimit{Nodes: 1, Limit: 100, Burst: 200}

	drl, err := parseDynamicRateLimit(jsonCfg)
	assert.NoError(t, err)
	assert.Contains(t, drl, wantCfg)
}

func Test_parseDynamicRateLimitConfigInvalid(t *testing.T) {
	jsonCfg := "[{\"noides\": 1,\"blurst\":100}]"

	drl, err := parseDynamicRateLimit(jsonCfg)
	assert.Error(t, err)
	assert.Nil(t, drl)
}

func TestSingleDynamicRateLimit(t *testing.T) {
	limit := 15.0
	burst := 30
	p := params{
		Logger: hivetest.Logger(t),
		Cfg: Config{
			CESMaxCEPsInCES:           100,
			CESSlicingMode:            identityMode,
			CESDynamicRateLimitConfig: "[{\"nodes\": 5, \"limit\": 15.0, \"burst\": 30}]",
		},
	}
	config, err := getRateLimitConfig(p)
	assert.NoError(t, err)
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
	rl := dynamicRateLimit{
		{Nodes: 15, Limit: 11.0, Burst: 22},
		{Nodes: 5, Limit: 5.0, Burst: 10},
		{Nodes: 25, Limit: 16.0, Burst: 32},
	}

	rlJson, err := json.Marshal(rl)
	assert.NoError(t, err)
	p := params{
		Logger: hivetest.Logger(t),
		Cfg: Config{
			CESMaxCEPsInCES:           100,
			CESSlicingMode:            identityMode,
			CESDynamicRateLimitConfig: string(rlJson),
		},
	}
	config, err := getRateLimitConfig(p)
	assert.NoError(t, err)
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
