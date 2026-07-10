// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"expvar"
	"time"

	"github.com/cilium/hive/cell"
)

type Metrics interface {
	ReconciliationDuration(moduleID cell.FullModuleID, name, operation string, duration time.Duration)
	ReconciliationErrors(moduleID cell.FullModuleID, name string, new, current int)

	PruneError(moduleID cell.FullModuleID, name string, err error)
	PruneDuration(moduleID cell.FullModuleID, name string, duration time.Duration)
}

const (
	OpUpdate = "update"
	OpDelete = "delete"
)

type ExpVarMetrics struct {
	root *expvar.Map

	ReconciliationCountVar         *expvar.Map
	ReconciliationDurationVar      *expvar.Map
	ReconciliationTotalErrorsVar   *expvar.Map
	ReconciliationCurrentErrorsVar *expvar.Map

	PruneCountVar         *expvar.Map
	PruneDurationVar      *expvar.Map
	PruneTotalErrorsVar   *expvar.Map
	PruneCurrentErrorsVar *expvar.Map
}

func metricKey(moduleID cell.FullModuleID, name string) string {
	if name == "" {
		return moduleID.String()
	}
	return moduleID.String() + "/" + name
}

func (m *ExpVarMetrics) PruneDuration(moduleID cell.FullModuleID, name string, duration time.Duration) {
	m.PruneDurationVar.AddFloat(metricKey(moduleID, name), duration.Seconds())
}

func (m *ExpVarMetrics) PruneError(moduleID cell.FullModuleID, name string, err error) {
	key := metricKey(moduleID, name)
	m.PruneCountVar.Add(key, 1)

	var intVar expvar.Int
	if err != nil {
		m.PruneTotalErrorsVar.Add(key, 1)
		intVar.Set(1)
	}
	m.PruneCurrentErrorsVar.Set(key, &intVar)
}

func (m *ExpVarMetrics) ReconciliationDuration(moduleID cell.FullModuleID, name, operation string, duration time.Duration) {
	m.ReconciliationDurationVar.AddFloat(metricKey(moduleID, name)+"/"+operation, duration.Seconds())
}

func (m *ExpVarMetrics) ReconciliationErrors(moduleID cell.FullModuleID, name string, new, current int) {
	key := metricKey(moduleID, name)
	m.ReconciliationCountVar.Add(key, 1)
	m.ReconciliationTotalErrorsVar.Add(key, int64(new))

	var intVar expvar.Int
	intVar.Set(int64(current))
	m.ReconciliationCurrentErrorsVar.Set(key, &intVar)
}

var _ Metrics = &ExpVarMetrics{}

func NewExpVarMetrics() *ExpVarMetrics {
	return newExpVarMetrics(true)
}

func NewUnpublishedExpVarMetrics() *ExpVarMetrics {
	return newExpVarMetrics(false)
}

func (m *ExpVarMetrics) Map() *expvar.Map {
	return m.root
}

func newExpVarMetrics(publish bool) *ExpVarMetrics {
	root := new(expvar.Map).Init()
	newMap := func(name string) *expvar.Map {
		if publish {
			return expvar.NewMap(name)
		}
		m := new(expvar.Map).Init()
		root.Set(name, m)
		return m
	}
	return &ExpVarMetrics{
		root:                           root,
		ReconciliationCountVar:         newMap("reconciliation_count"),
		ReconciliationDurationVar:      newMap("reconciliation_duration"),
		ReconciliationTotalErrorsVar:   newMap("reconciliation_total_errors"),
		ReconciliationCurrentErrorsVar: newMap("reconciliation_current_errors"),
		PruneCountVar:                  newMap("prune_count"),
		PruneDurationVar:               newMap("prune_duration"),
		PruneTotalErrorsVar:            newMap("prune_total_errors"),
		PruneCurrentErrorsVar:          newMap("prune_current_errors"),
	}
}
