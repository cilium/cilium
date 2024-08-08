// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	timeRate "golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/rate"
)

var testLimits = map[string]string{
	APIRequestEndpointCreate: "rate-limit:42/m,rate-burst:1",
	APIRequestEndpointDelete: "rate-limit:72/s,rate-burst:2",
}

func testLimitsKVString() string {
	var limits []string
	for k, v := range testLimits {
		limits = append(limits, k+"="+v)
	}
	return strings.Join(limits, ",")
}

func testLimitsJSONString() string {
	bs, err := json.Marshal(testLimits)
	if err != nil {
		panic(err)
	}
	return string(bs)
}

// TestRateLimiterConfigFlag checks that rateLimiterConfig is properly parsed from
// command-line flag.
func testRateLimiterConfig(t *testing.T, setConfig func(h *hive.Hive)) {
	var limiterSet *rate.APILimiterSet
	take := cell.Invoke(func(l *rate.APILimiterSet) { limiterSet = l })

	h := hive.New(rateLimiterCell, take)

	setConfig(h)
	tlog := hivetest.Logger(t)
	assert.Nil(t, h.Start(tlog, context.TODO()))

	l := limiterSet.Limiter(APIRequestEndpointCreate)
	assert.NotNil(t, l)

	p := l.Parameters()
	assert.Equal(t, timeRate.Limit(42.0/60.0), p.RateLimit)
	assert.Equal(t, 1, p.RateBurst)

	l = limiterSet.Limiter(APIRequestEndpointDelete)
	assert.NotNil(t, l)

	p = l.Parameters()
	assert.Equal(t, timeRate.Limit(72.0), p.RateLimit)
	assert.Equal(t, 2, p.RateBurst)

	assert.Nil(t, h.Stop(tlog, context.TODO()))
}

// TestRateLimiterConfigFlag checks that rateLimiterConfig is properly parsed from
// command-line flag.
func TestRateLimiterConfigFlag(t *testing.T) {
	testRateLimiterConfig(t,
		func(h *hive.Hive) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			h.RegisterFlags(flags)
			err := flags.Parse([]string{"--api-rate-limit", testLimitsKVString()})
			assert.Nil(t, err, "failed to parse flags")
		})
}

// TestRateLimiterConfigFile checks that rateLimiterConfig is properly parsed from
// a config file.
func TestRateLimiterConfigFile(t *testing.T) {
	testRateLimiterConfig(t,
		func(h *hive.Hive) {
			cfg := fmt.Sprintf("api-rate-limit: %s\n", testLimitsKVString())
			buf := bytes.NewReader([]byte(cfg))
			v := h.Viper()
			v.SetConfigType("yaml")
			err := v.ReadConfig(buf)
			assert.Nil(t, err, "failed to ReadConfig with Viper")
		})
}

// TestRateLimiterConfigDir checks that rateLimiterConfig is properly parsed from
// a config directory.
func TestRateLimiterConfigDir(t *testing.T) {
	// Test with k=v string
	testRateLimiterConfig(t,
		func(h *hive.Hive) {
			// option.InitConfig reads the files into a map[string]any which
			// is then merged into viper with MergeConfig. We're simulating that
			// here.
			configMap := map[string]any{
				"api-rate-limit": testLimitsKVString(),
			}
			v := h.Viper()
			err := v.MergeConfigMap(configMap)
			assert.Nil(t, err, "failed to MergeConfigMap with Viper")
		})

	// Test with JSON string
	testRateLimiterConfig(t,
		func(h *hive.Hive) {
			configMap := map[string]any{
				"api-rate-limit": testLimitsJSONString(),
			}
			v := h.Viper()
			err := v.MergeConfigMap(configMap)
			assert.Nil(t, err, "failed to MergeConfigMap with Viper")
		})
}
