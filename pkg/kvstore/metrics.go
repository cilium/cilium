// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const (
	metricDelete = "delete"
	metricRead   = "read"
	metricSet    = "set"
)

func GetScopeFromKey(key string) string {
	s := strings.SplitN(key, "/", 5)
	if len(s) < 4 {
		if len(key) >= 12 {
			return key[:12]
		}
		return key
	}
	return fmt.Sprintf("%s/%s", s[2], s[3])
}

func increaseMetric(key, kind, action string, duration time.Duration, err error) {
	if !option.Config.MetricsConfig.KVStoreOperationsDurationEnabled {
		return
	}
	namespace := GetScopeFromKey(key)
	outcome := metrics.Error2Outcome(err)
	metrics.KVStoreOperationsDuration.
		WithLabelValues(namespace, kind, action, outcome).Observe(duration.Seconds())
}

func trackEventQueued(key string, typ EventType, duration time.Duration) {
	if !option.Config.MetricsConfig.KVStoreEventsQueueDurationEnabled {
		return
	}
	metrics.KVStoreEventsQueueDuration.WithLabelValues(GetScopeFromKey(key), typ.String()).Observe(duration.Seconds())
}

func recordQuorumError(err string) {
	if !option.Config.MetricsConfig.KVStoreQuorumErrorsEnabled {
		return
	}
	metrics.KVStoreQuorumErrors.WithLabelValues(err).Inc()
}
