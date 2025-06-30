// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
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
	if !metrics.KVStoreOperationsDuration.IsEnabled() {
		return
	}
	namespace := GetScopeFromKey(key)
	outcome := metrics.Error2Outcome(err)
	metrics.KVStoreOperationsDuration.
		WithLabelValues(namespace, kind, action, outcome).Observe(duration.Seconds())
}

func trackEventQueued(scope string, typ EventType, duration time.Duration) {
	if !metrics.KVStoreEventsQueueDuration.IsEnabled() {
		return
	}
	metrics.KVStoreEventsQueueDuration.WithLabelValues(scope, typ.String()).Observe(duration.Seconds())
}

func recordQuorumError(err string) {
	if !metrics.KVStoreQuorumErrors.IsEnabled() {
		return
	}
	metrics.KVStoreQuorumErrors.WithLabelValues(err).Inc()
}
