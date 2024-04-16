// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	timeRate "golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/rate"
)

// TestRateLimiterConfigFlag checks that rateLimiterConfig is properly parsed from
// command-line flag.
func testRateLimiterConfig(t *testing.T, burst int, setConfig func(h *hive.Hive, limiter string, limits string)) {
	var limiterSet *rate.APILimiterSet
	take := cell.Invoke(func(l *rate.APILimiterSet) { limiterSet = l })

	h := hive.New(rateLimiterCell, take)

	setConfig(h, APIRequestEndpointCreate, fmt.Sprintf("rate-limit:42/m,rate-burst:%d", burst))
	tlog := hivetest.Logger(t)
	assert.Nil(t, h.Start(tlog, context.TODO()))

	l := limiterSet.Limiter(APIRequestEndpointCreate)
	assert.NotNil(t, l)

	p := l.Parameters()
	assert.Equal(t, timeRate.Limit(42.0/60.0), p.RateLimit)
	assert.Equal(t, burst, p.RateBurst)
	assert.Nil(t, h.Stop(tlog, context.TODO()))
}

// TestRateLimiterConfigFlag checks that rateLimiterConfig is properly parsed from
// command-line flag.
func TestRateLimiterConfigFlag(t *testing.T) {
	testRateLimiterConfig(t, 1234,
		func(h *hive.Hive, limiter string, limits string) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			h.RegisterFlags(flags)
			err := flags.Parse([]string{"--api-rate-limit", limiter + "=" + limits})
			assert.Nil(t, err, "failed to parse flags")
		})
}

// TestRateLimiterConfigFile checks that rateLimiterConfig is properly parsed from
// a config file.
func TestRateLimiterConfigFile(t *testing.T) {
	testRateLimiterConfig(t, 1235,
		func(h *hive.Hive, limiter string, limits string) {
			cfg := fmt.Sprintf("api-rate-limit:\n  %s: %s\n", limiter, limits)
			buf := bytes.NewReader([]byte(cfg))
			v := h.Viper()
			v.SetConfigType("yaml")
			err := v.ReadConfig(buf)
			assert.Nil(t, err, "failed to ReadConfig with Viper")
		})
}
