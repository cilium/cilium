// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"os/exec"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
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

		reconciler.New[*tables.IPSet],
		newReconcilerConfig,
		newOps,
	),
	cell.ProvidePrivate(func(logger logrus.FieldLogger) *ipset {
		return &ipset{
			executable: funcExecutable(func(ctx context.Context, name string, arg ...string) ([]byte, error) {
				return exec.CommandContext(ctx, name, arg...).Output()
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

func newReconcilerConfig(
	ops reconciler.Operations[*tables.IPSet],
) reconciler.Config[*tables.IPSet] {
	return reconciler.Config[*tables.IPSet]{
		FullReconcilationInterval: 10 * time.Second,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   5 * time.Second,
		IncrementalRoundSize:      100,
		GetObjectStatus:           (*tables.IPSet).GetStatus,
		WithObjectStatus:          (*tables.IPSet).WithStatus,
		Operations:                ops,
	}
}
