// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
)

type rateLimit struct {
	Nodes int
	Limit float64
	Burst int
}

type rateLimitConfig struct {
	current          rateLimit
	dynamicRateLimit []rateLimit

	rateLimiter *workqueue.BucketRateLimiter

	logger logrus.FieldLogger
}

func getRateLimitConfig(p params) rateLimitConfig {
	var dynamicRateLimit []rateLimit
	if p.Cfg.CESEnableDynamicRateLimit {
		var err error
		dynamicRateLimit, err = parseDynamicRateLimit(p.Cfg.CESDynamicRateLimitNodes, p.Cfg.CESDynamicRateLimitQPSLimit, p.Cfg.CESDynamicRateLimitQPSBurst)
		if err != nil {
			p.Logger.WithError(err).Warn("Couldn't parse dynamic rate limit config")
		}
	}
	rlc := rateLimitConfig{
		current: rateLimit{
			Limit: p.Cfg.CESWriteQPSLimit,
			Burst: p.Cfg.CESWriteQPSBurst,
		},
		dynamicRateLimit: dynamicRateLimit,
		logger:           p.Logger,
	}

	if rlc.hasDynamicRateLimiting() {
		rlc.updateRateLimitWithNodes(0, true)
	}
	rlc.rateLimiter = &workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(rlc.current.Limit), rlc.current.Burst)}
	return rlc
}

func parseDynamicRateLimit(nodes []string, limits []string, bursts []string) ([]rateLimit, error) {
	if len(nodes) != len(limits) || len(nodes) != len(bursts) {
		return nil, fmt.Errorf("Length of the %s, %s and %s needs to be the same", CESDynamicRateLimitNodes, CESDynamicRateLimitQPSLimit, CESDynamicRateLimitQPSBurst)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("Dynamic rate limit is enabled but the flags specifying it are not set")
	}
	dynamicRateLimit := make([]rateLimit, len(nodes))
	for i := 0; i < len(nodes); i++ {
		node, err := strconv.Atoi(nodes[i])
		if err != nil {
			return nil, fmt.Errorf("unable to convert node value %q to int", nodes[i])
		}
		dynamicRateLimit[i].Nodes = node

		limit, err := strconv.ParseFloat(limits[i], 64)
		if err != nil {
			return nil, fmt.Errorf("unable to convert limit value %q to float", limits[i])
		}
		dynamicRateLimit[i].Limit = limit

		burst, err := strconv.Atoi(bursts[i])
		if err != nil {
			return nil, fmt.Errorf("unable to convert burst value %q to int", bursts[i])
		}
		dynamicRateLimit[i].Burst = burst
	}
	sort.Slice(dynamicRateLimit, func(i, j int) bool {
		return dynamicRateLimit[i].Nodes < dynamicRateLimit[j].Nodes
	})
	return dynamicRateLimit, nil
}

func (rlc *rateLimitConfig) hasDynamicRateLimiting() bool {
	return rlc.dynamicRateLimit != nil
}

func (rlc *rateLimitConfig) getDelay() time.Duration {
	return rlc.rateLimiter.Reserve().Delay()
}

func (rlc *rateLimitConfig) updateRateLimiterWithNodes(nodes int) bool {
	rlc.logger.Info("Updating rate limit with nodes: ", nodes)
	changed := rlc.updateRateLimitWithNodes(nodes, false)
	if changed {
		rlc.rateLimiter.SetBurst(rlc.current.Burst)
		rlc.rateLimiter.SetLimit(rate.Limit(rlc.current.Limit))
	}
	return changed
}

func (rlc *rateLimitConfig) updateRateLimitWithNodes(nodes int, force bool) bool {
	if !rlc.hasDynamicRateLimiting() {
		return false
	}

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
		if rlc.current.Limit == 0 {
			rlc.current.Limit = CESControllerWorkQueueQPSLimit
		} else if rlc.current.Limit > CESWriteQPSLimitMax {
			rlc.current.Limit = CESWriteQPSLimitMax
		}
		if rlc.current.Burst == 0 {
			rlc.current.Burst = CESControllerWorkQueueBurstLimit
		} else if rlc.current.Burst > CESWriteQPSBurstMax {
			rlc.current.Burst = CESWriteQPSBurstMax
		}
		return true
	}
	return false
}
