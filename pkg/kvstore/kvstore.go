// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"strings"

	"github.com/cilium/cilium/pkg/time"
)

// Value is an abstraction of the data stored in the kvstore as well as the
// mod revision of that data.
type Value struct {
	Data        []byte
	ModRevision uint64
	LeaseID     int64
}

// KeyValuePairs is a map of key=value pairs
type KeyValuePairs map[string]Value

const (
	// BaseKeyPrefix is the base prefix that should be used for all keys
	BaseKeyPrefix = "cilium"

	// StatePrefix is the kvstore prefix used to store the Cilium's state.
	StatePrefix = BaseKeyPrefix + "/state"

	// CachePrefix is the kvstore prefix used to store the information retrieved
	// from a remote cluster and cached locally by KVStoreMesh.
	CachePrefix = BaseKeyPrefix + "/cache"

	// InitLockPath is the path to the init lock to test quorum
	InitLockPath = BaseKeyPrefix + "/.initlock"

	// HeartbeatPath is the path to the key at which the operator updates
	// the heartbeat
	HeartbeatPath = BaseKeyPrefix + "/.heartbeat"

	// ClusterConfigPrefix is the kvstore prefix to cluster configuration
	ClusterConfigPrefix = BaseKeyPrefix + "/cluster-config"

	// SyncedPrefix is the kvstore prefix used to convey whether
	// synchronization from an external source has completed for a given prefix
	SyncedPrefix = BaseKeyPrefix + "/synced"

	// HeartbeatWriteInterval is the interval in which the heartbeat key at
	// HeartbeatPath is updated
	HeartbeatWriteInterval = time.Minute
)

// StateToCachePrefix converts a kvstore prefix starting with "cilium/state"
// (holding the cilium state) to the corresponding one holding cached information
// from another kvstore (that is, "cilium/cache").
func StateToCachePrefix(prefix string) string {
	if strings.HasPrefix(prefix, StatePrefix) {
		return strings.Replace(prefix, StatePrefix, CachePrefix, 1)
	}
	return prefix
}
