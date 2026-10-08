// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"strings"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const (
	metricDelete = "delete"
	metricRead   = "read"
	metricSet    = "set"
)

// scopeOther is the scope associated with keys not matching any known layout.
const scopeOther = "other"

// GetScopeFromKey returns the scope associated with the given key, to be used
// as metric label. The returned value is guaranteed to have bounded cardinality:
//   - cilium/{state,cache}/<resource>/<version>[/...] -> <resource>/<version>
//   - cilium/synced/<cluster>/<key> -> synced/<scope of key>, or synced
//   - cilium/<name>[/...] -> <name>, stripped of any leading dot
//   - anything else -> other
func GetScopeFromKey(key string) string {
	s := strings.SplitN(key, "/", 4)
	if len(s) < 2 || s[0] != BaseKeyPrefix || s[1] == "" {
		return scopeOther
	}

	switch s[1] {
	case "state", "cache":
		if len(s) < 4 {
			return scopeOther
		}
		version, _, _ := strings.Cut(s[3], "/")
		if s[2] == "" || version == "" {
			return scopeOther
		}
		return s[2] + "/" + version
	case "synced":
		// The synced key is the concatenation of the prefix, the source
		// cluster name and the synced prefix (e.g., cilium/state/nodes/v1).
		if len(s) < 4 {
			return "synced"
		}
		if scope := GetScopeFromKey(s[3]); scope != scopeOther {
			return "synced/" + scope
		}
		return "synced"
	default:
		if name := strings.TrimPrefix(s[1], "."); name != "" {
			return name
		}
		return scopeOther
	}
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
