// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"fmt"
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// GCInterval is the interval in which allocator identities are
	// attempted to be collected
	GCInterval = "identity-gc-interval"

	// GCRateInterval is the interval used for rate limiting the GC of
	// identities.
	GCRateInterval = "identity-gc-rate-interval"

	// GCRateLimit is the maximum identities used for rate limiting the
	// GC of identities.
	GCRateLimit = "identity-gc-rate-limit"

	// HeartbeatTimeout is the timeout used to GC identities from k8s
	HeartbeatTimeout = "identity-heartbeat-timeout"
)

// GCCell is a cell that implements a periodic Cilium identities
// garbage collector.
// The GC subscribes to identities events to mark all the related identities
// as alive. If an identity has no activity for a prolonged interval,
// it is first marked for deletion and eventually deleted.
var GCCell = cell.Module(
	"k8s-identities-gc",
	"Cilium identities garbage collector",

	cell.Config(defaultGCConfig),

	cell.Provide(newGC),

	// Invoke forces the instantiation of the identity gc
	cell.Invoke(func(*GC) {}),
)

// GCConfig contains the configuration for the identity-gc.
type GCConfig struct {
	GCInterval       time.Duration `mapstructure:"identity-gc-interval"`
	HeartbeatTimeout time.Duration `mapstructure:"identity-heartbeat-timeout"`

	GCRateInterval time.Duration `mapstructure:"identity-gc-rate-interval"`
	GCRateLimit    int64         `mapstructure:"identity-gc-rate-limit"`
}

var defaultGCConfig = GCConfig{
	GCInterval:       defaults.KVstoreLeaseTTL,
	HeartbeatTimeout: 2 * defaults.KVstoreLeaseTTL,

	GCRateInterval: time.Minute,
	GCRateLimit:    2500,
}

func (def GCConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration(GCInterval, def.GCInterval, "GC interval for security identities")
	flags.Duration(HeartbeatTimeout, def.HeartbeatTimeout, "Timeout after which identity expires on lack of heartbeat")
	flags.Duration(GCRateInterval, def.GCRateInterval,
		"Interval used for rate limiting the GC of security identities")
	flags.Int64(GCRateLimit, def.GCRateLimit,
		fmt.Sprintf("Maximum number of security identities that will be deleted within the %s", GCRateInterval))
}

// GCSharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type GCSharedConfig struct {
	// IdentityAllocationMode specifies what mode to use for identity allocation
	IdentityAllocationMode string

	// EnableMetrics enables prometheus metrics
	EnableMetrics bool

	// ClusterName is the name of the cluster
	ClusterName string

	// K8sNamespace is the name of the namespace in which Cilium is
	// deployed in when running in Kubernetes mode
	K8sNamespace string

	// ClusterID is the unique identifier of the cluster
	ClusterID uint32
}
