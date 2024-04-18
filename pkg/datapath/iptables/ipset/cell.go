// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"os/exec"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// Cell exposes methods to add and remove node IPs from the kernel IP sets.
// The sets are in turn referenced by iptables rules to exclude traffic
// to cluster nodes from being masqueraded.
// There are two distinct sets, one for IPv4 addresses and one for IPv6
// addresses.
// Internally, the cell stores the desired IP sets state in a StateDB table
// and uses a reconciler to update the realized state (that is, the actual
// kernel IP sets).
// Other sets that do not pertain to Cilium configuration are not changed
// in any way.
var Cell = cell.Module(
	"ipset",
	"Handle kernel IP sets configuration for Cilium",

	cell.Provide(newIPSetManager),

	cell.ProvidePrivate(
		tables.NewIPSetTable,

		reconciler.New[*tables.IPSetEntry],
		newReconcilerConfig,
		newOps,
	),
	cell.ProvidePrivate(func(logger logrus.FieldLogger) *ipset {
		return &ipset{
			executable: funcExecutable(func(ctx context.Context, name string, stdin string, arg ...string) ([]byte, error) {
				cmd := exec.CommandContext(ctx, name, arg...)
				cmd.Stdin = strings.NewReader(stdin)
				return cmd.Output()
			}),
			log: logger,
		}
	}),
	cell.ProvidePrivate(func(cfg *option.DaemonConfig) config {
		return config{NodeIPSetNeeded: cfg.NodeIpsetNeeded()}
	}),
)

type config struct {
	NodeIPSetNeeded bool
}

func newReconcilerConfig(ops *ops, tbl statedb.RWTable[*tables.IPSetEntry]) reconciler.Config[*tables.IPSetEntry] {
	return reconciler.Config[*tables.IPSetEntry]{
		Table:                     tbl,
		FullReconcilationInterval: 30 * time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   5 * time.Second,
		GetObjectStatus:           (*tables.IPSetEntry).GetStatus,
		SetObjectStatus:           (*tables.IPSetEntry).SetStatus,
		CloneObject:               (*tables.IPSetEntry).Clone,
		Operations:                ops,
		BatchOperations:           ops,

		// Set the maximum batch size to 100, and limit the incremental
		// reconciliation to once every 10ms, giving us maximum throughput
		// of 1000/10 * 100 = 10000 per second.
		IncrementalRoundSize: 100,

		// Set the rate limiter to accumulate a batch of entries to reconcile.
		RateLimiter: rate.NewLimiter(rate.Every(10*time.Millisecond), 1),
	}
}
