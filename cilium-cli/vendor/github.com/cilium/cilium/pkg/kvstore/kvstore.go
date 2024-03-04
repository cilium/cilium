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
	SessionID   string
}

// KeyValuePairs is a map of key=value pairs
type KeyValuePairs map[string]Value

const (
	// BaseKeyPrefix is the base prefix that should be used for all keys
	BaseKeyPrefix = "cilium"

	// InitLockPath is the path to the init lock to test quorum
	InitLockPath = BaseKeyPrefix + "/.initlock"

	// HeartbeatPath is the path to the key at which the operator updates
	// the heartbeat
	HeartbeatPath = BaseKeyPrefix + "/.heartbeat"

	// HasClusterConfigPath is the path to the key used to convey that the cluster
	// configuration will be eventually created, and remote cilium agents shall
	// wait until it is present. If this key is not set, the cilium configuration
	// might, or might not, be configured, but the agents will continue regardless,
	// falling back to the backward compatible behavior. It must be set before that
	// the agents have the possibility to connect to the kvstore (that is, when
	// it is not yet exposed). The corresponding values is ignored.
	HasClusterConfigPath = BaseKeyPrefix + "/.has-cluster-config"

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
	if strings.HasPrefix(prefix, "cilium/state") {
		return strings.Replace(prefix, "cilium/state", "cilium/cache", 1)
	}
	return prefix
}
