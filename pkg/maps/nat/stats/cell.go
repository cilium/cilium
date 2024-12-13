// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/hive/cell"

	"github.com/spf13/pflag"
)

const (
	TableName                   = "nat-stats"
	maxNatMapStatKStoredEntries = 4096
	minNatMapStatKStoredEntries = 1
	natMapStatsEntriesName      = "nat-map-stats-entries"
)

// Cell exports a module providing functionality for computing NAT map stats.
// This uses provided pkg/maps/nat.(Cell) maps to efficiently walk the nat map
// and compute the top-k most used connection tuples.
// In this context, a "connection tuple" refers to the 4-tuple:
//
// {port, egressIP, remoteEndpointIP, remoteEndpointPort}
//
// Which defines a distinct set of translated connections for which the source IP is the
// egress IP, who all share the same endpoint address.
// Egress source ports are allocated by the datapath and, in some cases, can be
// prone to exhaustion or allocation failures if the connection tuple already
// has many connections to the same endpoint.
//
// The nat-stats module exposes this data as both prometheus metrics and via a
// exported statedb.Table[NatMapStats] for other modules to consume.
var Cell = cell.Module(
	"nat-stats",
	"Aggregates stats for NAT maps",
	metrics.Metric(newMetrics),
	cell.ProvidePrivate(newTables),
	cell.Provide(
		func(m Metrics) natMetrics {
			return m
		},
		newStats,
		statedb.RWTable[NatMapStats].ToTable,
	),
	cell.Config(Config{
		// NATMapStatInterval is how often the map is counted, 30 seconds was chosen as a reasonable starting
		// point that avoids excess cpu/mem usage but provides relatively up-to-date data.
		NATMapStatInterval: 30 * time.Second,
		// NatMapStatKStoredEntries is the number of the top-k entries to store, up to a max of 4096.
		NatMapStatKStoredEntries: 32,
	}),
	cell.Invoke(func(_ *Stats) {}),
)

type Metrics struct {
	LocalPorts metric.Vec[metric.Gauge]
}

type natMetrics interface {
	updateLocalPorts(family nat.IPFamily, count, maxPorts int)
}

func (m Metrics) updateLocalPorts(family nat.IPFamily, count, maxPorts int) {
	m.LocalPorts.WithLabelValues(family.String()).Set(float64(count) / float64(maxPorts))
}

func newMetrics() Metrics {
	return Metrics{
		LocalPorts: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Help:      "Max saturation of source ports on a egress-ip/external endpoint tuple",
			Name:      "nat_endpoint_max_connection",
		}, metric.Labels{
			{Name: "family", Values: metric.NewValues(nat.IPv4.String(), nat.IPv6.String())},
		}),
	}
}

type Config struct {
	NATMapStatInterval       time.Duration `mapstructure:"nat-map-stats-interval"`
	NatMapStatKStoredEntries int           `mapstructure:"nat-map-stats-entries"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("nat-map-stats-interval", def.NATMapStatInterval, "Interval upon which nat maps are iterated for stats")
	flags.Int("nat-map-stats-entries", def.NatMapStatKStoredEntries, "Number k top stats entries to store locally in statedb")
}

var (
	Index = statedb.Index[NatMapStats, string]{
		Name: "byTuple",
		FromObject: func(s NatMapStats) index.KeySet {
			return index.NewKeySet(s.Key())
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

func newTables(db *statedb.DB) (statedb.RWTable[NatMapStats], error) {
	statusTable, err := statedb.NewTable(TableName, Index)
	if err != nil {
		return nil, err
	}
	if err := db.RegisterTable(statusTable); err != nil {
		return nil, err
	}
	return statusTable, nil
}
