// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"expvar"
	"time"

	"github.com/cilium/hive/cell"
)

type Metrics interface {
	ReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration)
	ReconciliationErrors(moduleID cell.FullModuleID, new, current int)

	PruneError(moduleID cell.FullModuleID, err error)
	PruneDuration(moduleID cell.FullModuleID, duration time.Duration)
}

const (
	OpUpdate = "update"
	OpDelete = "delete"
)

type ExpVarMetrics struct {
	ReconciliationCountVar         *expvar.Map
	ReconciliationDurationVar      *expvar.Map
	ReconciliationTotalErrorsVar   *expvar.Map
	ReconciliationCurrentErrorsVar *expvar.Map

	PruneCountVar         *expvar.Map
	PruneDurationVar      *expvar.Map
	PruneTotalErrorsVar   *expvar.Map
	PruneCurrentErrorsVar *expvar.Map
}

func (m *ExpVarMetrics) PruneDuration(moduleID cell.FullModuleID, duration time.Duration) {
	m.PruneDurationVar.AddFloat(moduleID.String(), duration.Seconds())
}

func (m *ExpVarMetrics) PruneError(moduleID cell.FullModuleID, err error) {
	m.PruneCountVar.Add(moduleID.String(), 1)
	m.PruneTotalErrorsVar.Add(moduleID.String(), 1)

	var intVar expvar.Int
	if err != nil {
		intVar.Set(1)
	}
	m.PruneCurrentErrorsVar.Set(moduleID.String(), &intVar)
}

func (m *ExpVarMetrics) ReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration) {
	m.ReconciliationDurationVar.AddFloat(moduleID.String()+"/"+operation, duration.Seconds())
}

func (m *ExpVarMetrics) ReconciliationErrors(moduleID cell.FullModuleID, new, current int) {
	m.ReconciliationCountVar.Add(moduleID.String(), 1)
	m.ReconciliationTotalErrorsVar.Add(moduleID.String(), int64(new))

	var intVar expvar.Int
	intVar.Set(int64(current))
	m.ReconciliationCurrentErrorsVar.Set(moduleID.String(), &intVar)
}

var _ Metrics = &ExpVarMetrics{}

func NewExpVarMetrics() *ExpVarMetrics {
	return newExpVarMetrics(true)
}

func NewUnpublishedExpVarMetrics() *ExpVarMetrics {
	return newExpVarMetrics(false)
}

func newExpVarMetrics(publish bool) *ExpVarMetrics {
	newMap := func(name string) *expvar.Map {
		if publish {
			return expvar.NewMap(name)
		}
		return new(expvar.Map).Init()
	}
	return &ExpVarMetrics{
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
