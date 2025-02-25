// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type rateLimit struct {
	Nodes int
	Limit float64
	Burst int
}

type rateLimitConfig struct {
	current          rateLimit
	dynamicRateLimit dynamicRateLimit

	rateLimiter *rate.Limiter

	logger *slog.Logger
}

type dynamicRateLimit []rateLimit

func getRateLimitConfig(p params) (rateLimitConfig, error) {
	rlc := rateLimitConfig{
		logger: p.Logger,
	}
	parsed, err := parseDynamicRateLimit(p.Cfg.CESDynamicRateLimitConfig)
	if err != nil {
		return rlc, fmt.Errorf("Couldn't parse CES rate limit config: %w", err)
	}
	rlc.dynamicRateLimit = parsed
	rlc.updateRateLimitWithNodes(0, true)
	rlc.rateLimiter = rate.NewLimiter(rate.Limit(rlc.current.Limit), rlc.current.Burst)
	return rlc, nil
}

func parseDynamicRateLimit(cfg string) (dynamicRateLimit, error) {
	if len(cfg) == 0 {
		return nil, fmt.Errorf("invalid: config is empty")
	}
	dynamicRateLimit := dynamicRateLimit{}
	decoder := json.NewDecoder(strings.NewReader(cfg))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&dynamicRateLimit); err != nil {
		return nil, err
	}

	sort.Slice(dynamicRateLimit, func(i, j int) bool {
		return dynamicRateLimit[i].Nodes < dynamicRateLimit[j].Nodes
	})
	return dynamicRateLimit, nil
}

func (rlc *rateLimitConfig) getDelay() time.Duration {
	return rlc.rateLimiter.Reserve().Delay()
}

func (rlc *rateLimitConfig) updateRateLimiterWithNodes(nodes int) bool {
	changed := rlc.updateRateLimitWithNodes(nodes, false)
	if changed {
		rlc.logger.Info("Updating rate limit",
			logfields.Nodes, nodes,
			logfields.WorkQueueQPSLimit, rlc.current.Limit,
			logfields.WorkQueueBurstLimit, rlc.current.Burst)

		rlc.rateLimiter.SetBurst(rlc.current.Burst)
		rlc.rateLimiter.SetLimit(rate.Limit(rlc.current.Limit))
	}
	return changed
}

func (rlc *rateLimitConfig) updateRateLimitWithNodes(nodes int, force bool) bool {
	index := 0
	for ; index < len(rlc.dynamicRateLimit)-1; index++ {
		if rlc.dynamicRateLimit[index+1].Nodes > nodes {
			break
		}
	}
	changed := rlc.current.Nodes != rlc.dynamicRateLimit[index].Nodes

	if changed || force {
		rlc.current = rateLimit{
			Nodes: rlc.dynamicRateLimit[index].Nodes,
			Limit: rlc.dynamicRateLimit[index].Limit,
			Burst: rlc.dynamicRateLimit[index].Burst,
		}
		if rlc.current.Limit > CESWriteQPSLimitMax {
			rlc.current.Limit = CESWriteQPSLimitMax
		}
		if rlc.current.Burst > CESWriteQPSBurstMax {
			rlc.current.Burst = CESWriteQPSBurstMax
		}
		return true
	}
	return false
}
