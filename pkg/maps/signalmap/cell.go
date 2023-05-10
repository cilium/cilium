// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signalmap

import (
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell initializes and manages the config map.
var Cell = cell.Module(
	"signal-map",
	"eBPF map signal passes wakeup events from Cilium datapath",

	cell.Provide(newMap),
)

// PerfReader is an interface for reading from perf records. Implementations need to be safe to call
// from multiple goroutines.
type PerfReader interface {
	Read() (perf.Record, error)
	Pause() error
	Resume() error
	Close() error
}

type Map interface {
	NewReader() (PerfReader, error)
	MapName() string
}

func newMap(log logrus.FieldLogger, lifecycle hive.Lifecycle) bpf.MapOut[Map] {
	possibleCPUs := common.GetNumPossibleCPUs(log)
	signalmap := initMap(possibleCPUs)

	log.Debugf("signalmap.newMap: %v", signalmap)

	lifecycle.Append(hive.Hook{
		OnStart: func(startCtx hive.HookContext) error {
			return signalmap.open()
		},
		OnStop: func(stopCtx hive.HookContext) error {
			return signalmap.close()
		},
	})

	return bpf.NewMapOut(Map(signalmap))
}
