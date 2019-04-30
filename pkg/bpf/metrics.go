// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricLabelOperation = "operation"
	metricLabelMapName   = "mapName"

	metricOpCreate           = "create"
	metricOpUpdate           = "update"
	metricOpLookup           = "lookup"
	metricOpDelete           = "delete"
	metricOpGetNextKey       = "getNextKey"
	metricOpObjPin           = "objPin"
	metricOpObjGet           = "objGet"
	metricOpGetFDByID        = "getFDByID"
	metricOpProgGetNextID    = "progGetNextID"
	metricOpObjGetInfoByFD   = "getInfoByFD"
	metricOpPerfEventOpen    = "perfEventOpen"
	metricOpPerfEventEnable  = "perfEventEnable"
	metricOpPerfEventDisable = "perfEventDisable"
)

var (
	metricSyscallDuration *prometheus.HistogramVec
	metricMapOps          *prometheus.CounterVec
)

func Init() {
	if !option.Config.IsSubsysMetricEnabled(metrics.SubsystemBPFMask) {
		return
	}

	metricSyscallDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Subsystem: metrics.SubsystemBPF,
		Name:      "syscall_duration_seconds",
		Help:      "Duration of BPF system calls",
	}, []string{metricLabelOperation, metrics.LabelOutcome})

	if err := metrics.Register(metricSyscallDuration); err != nil {
		log.WithError(err).Fatal("unable to register prometheus metric")
	}

	metricMapOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: metrics.SubsystemBPF,
		Name:      "map_ops_total",
		Help:      "Total operations on map, tagged by map name",
	},
		[]string{metricLabelMapName, metricLabelOperation, metrics.LabelOutcome})

	if err := metrics.Register(metricMapOps); err != nil {
		log.WithError(err).Fatal("unable to register prometheus metric")
	}
}
