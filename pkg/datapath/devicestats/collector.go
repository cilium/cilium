// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicestats

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"device-metrics",
	"Exports generic link statistics for Cilium-managed devices to Prometheus",
	cell.Invoke(registerCollector),
)

// deviceLister supplies the names of interfaces to collect stats for. It
// decouples the collector from statedb so unit tests can use a fixed list.
type deviceLister interface {
	Names() []string
}

type statedbDeviceLister struct {
	db    *statedb.DB
	table statedb.Table[*tables.Device]
}

func (l statedbDeviceLister) Names() []string {
	var names []string
	for dev := range l.table.List(l.db.ReadTxn(), tables.DevicesBySelected(true)) {
		names = append(names, dev.Name)
	}
	return names
}

const (
	directionIngress = "INGRESS"
	directionEgress  = "EGRESS"
)

type collector struct {
	reader      Reader
	devices     deviceLister
	bytesDesc   *prometheus.Desc
	packetsDesc *prometheus.Desc
}

func newCollector(reader Reader, devices deviceLister) *collector {
	return &collector{
		reader:  reader,
		devices: devices,
		bytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "device", "bytes_total"),
			"Total number of bytes seen on a Cilium-managed device, tagged by ingress/egress direction",
			[]string{"device", metrics.LabelDirection}, nil,
		),
		packetsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "device", "packets_total"),
			"Total number of packets seen on a Cilium-managed device, tagged by ingress/egress direction",
			[]string{"device", metrics.LabelDirection}, nil,
		),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytesDesc
	ch <- c.packetsDesc
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	for _, dev := range c.devices.Names() {
		stats, err := c.reader.Stats(dev)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.bytesDesc, prometheus.CounterValue, float64(stats.RxBytes), dev, directionIngress)
		ch <- prometheus.MustNewConstMetric(c.bytesDesc, prometheus.CounterValue, float64(stats.TxBytes), dev, directionEgress)
		ch <- prometheus.MustNewConstMetric(c.packetsDesc, prometheus.CounterValue, float64(stats.RxPackets), dev, directionIngress)
		ch <- prometheus.MustNewConstMetric(c.packetsDesc, prometheus.CounterValue, float64(stats.TxPackets), dev, directionEgress)
	}
}

func registerCollector(logger *slog.Logger, db *statedb.DB, table statedb.Table[*tables.Device]) {
	c := newCollector(NewNetlinkReader(), statedbDeviceLister{db: db, table: table})
	if err := metrics.Register(c); err != nil {
		logger.Error("Failed to register device metrics collector", logfields.Error, err)
	}
}
