// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"expvar"
	"time"

	"github.com/cilium/hive/cell"
)

type Metrics interface {
	IncrementalReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration)
	IncrementalReconciliationErrors(moduleID cell.FullModuleID, newErrors, currentErrors int)

	FullReconciliationErrors(moduleID cell.FullModuleID, errs []error)
	FullReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration)
}

const (
	OpUpdate = "update"
	OpDelete = "delete"
	OpPrune  = "prune"
)

type ExpVarMetrics struct {
	IncrementalReconciliationCountVar         *expvar.Map
	IncrementalReconciliationDurationVar      *expvar.Map
	IncrementalReconciliationTotalErrorsVar   *expvar.Map
	IncrementalReconciliationCurrentErrorsVar *expvar.Map

	FullReconciliationCountVar         *expvar.Map
	FullReconciliationDurationVar      *expvar.Map
	FullReconciliationTotalErrorsVar   *expvar.Map
	FullReconciliationCurrentErrorsVar *expvar.Map
}

func (m *ExpVarMetrics) FullReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration) {
	m.FullReconciliationDurationVar.AddFloat(moduleID.String()+"/"+operation, duration.Seconds())
}

func (m *ExpVarMetrics) FullReconciliationErrors(moduleID cell.FullModuleID, errs []error) {
	m.FullReconciliationCountVar.Add(moduleID.String(), 1)
	m.FullReconciliationTotalErrorsVar.Add(moduleID.String(), int64(len(errs)))

	var intVar expvar.Int
	intVar.Set(int64(len(errs)))
	m.FullReconciliationCurrentErrorsVar.Set(moduleID.String(), &intVar)
}

func (m *ExpVarMetrics) IncrementalReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration) {
	m.IncrementalReconciliationDurationVar.AddFloat(moduleID.String()+"/"+operation, duration.Seconds())
}

func (m *ExpVarMetrics) IncrementalReconciliationErrors(moduleID cell.FullModuleID, newErrors, currentErrors int) {
	m.IncrementalReconciliationCountVar.Add(moduleID.String(), 1)
	m.IncrementalReconciliationTotalErrorsVar.Add(moduleID.String(), int64(newErrors))

	var intVar expvar.Int
	intVar.Set(int64(currentErrors))
	m.IncrementalReconciliationCurrentErrorsVar.Set(moduleID.String(), &intVar)
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
		IncrementalReconciliationCountVar:         newMap("incremental_reconciliation_count"),
		IncrementalReconciliationDurationVar:      newMap("incremental_reconciliation_duration"),
		IncrementalReconciliationTotalErrorsVar:   newMap("incremental_reconciliation_total_errors"),
		IncrementalReconciliationCurrentErrorsVar: newMap("incremental_reconciliation_current_errors"),
		FullReconciliationCountVar:                newMap("full_reconciliation_count"),
		FullReconciliationDurationVar:             newMap("full_reconciliation_duration"),
		FullReconciliationTotalErrorsVar:          newMap("full_reconciliation_total_errors"),
		FullReconciliationCurrentErrorsVar:        newMap("full_reconciliation_current_errors"),
	}
}
