// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamiclifecycle

import (
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/dynamicconfig"

	"github.com/cilium/cilium/pkg/time"
)

const TableName = "dynamic-features"

var (
	featureIndex = statedb.Index[*DynamicFeature, DynamicFeatureName]{
		Name: "feature",
		FromObject: func(t *DynamicFeature) index.KeySet {
			return index.NewKeySet(index.Stringer(t.Name))
		},
		FromKey:    index.Stringer[DynamicFeatureName],
		FromString: index.FromString,
		Unique:     true,
	}

	ByFeature = featureIndex.Query
)

type tableParams struct {
	cell.In

	DB                      *statedb.DB
	ManagerConfig           config
	DynamicConfigCellConfig dynamicconfig.Config
	FeatureRegistrations    []featureRegistration `group:"dynamiclifecycle-registrations"`
}

type DynamicFeatureName string

func (f DynamicFeatureName) String() string {
	return string(f)
}

type DynamicFeature struct {
	Name          DynamicFeatureName   // DynamicFeature name
	Hooks         []cell.HookInterface // Lifecycle hooks
	Deps          []DynamicFeatureName // DynamicFeature dependencies
	Enabled       bool                 // lifecycle enablement status
	IsRunning     bool                 // lifecycle running status
	Status        reconciler.Status    // reconciliation status
	StartedAt     time.Time            // last lifecycle start time
	StoppedAt     time.Time            // last lifecycle stop time
	StartDuration time.Duration        // last lifecycle start time duration
}

func (tl *DynamicFeature) TableHeader() []string {
	return []string{
		"Name",
		"Hooks",
		"Deps",
		"Enabled",
		"IsRunning",
		"Status",
		"StartedAt",
		"StoppedAt",
		"StartDuration",
	}
}

func (tl *DynamicFeature) TableRow() []string {
	return []string{
		tl.Name.String(),
		strconv.Itoa(len(tl.Hooks)),
		strconv.Itoa(len(tl.Deps)),
		strconv.FormatBool(tl.Enabled),
		strconv.FormatBool(tl.IsRunning),
		tl.Status.String(),
		tl.StartedAt.String(),
		tl.StoppedAt.String(),
		tl.StartDuration.String(),
	}
}

// GetStatus returns the reconciliation status. Used to provide the
// reconciler access to it.
func (tl *DynamicFeature) getStatus() reconciler.Status {
	return tl.Status
}

// SetStatus sets the reconciliation status.
// Used by the reconciler to update the reconciliation status of the DynamicFeature.
func (tl *DynamicFeature) setStatus(newStatus reconciler.Status) *DynamicFeature {
	tl.Status = newStatus
	return tl
}

// Clone returns a shallow copy of the DynamicFeature.
func (tl *DynamicFeature) Clone() *DynamicFeature {
	tl2 := *tl
	return &tl2
}

func newDynamicFeature(name DynamicFeatureName, deps []DynamicFeatureName, hooks []cell.HookInterface) *DynamicFeature {
	return &DynamicFeature{
		Name:          name,
		Deps:          deps,
		Hooks:         hooks,
		IsRunning:     false,
		Enabled:       false,
		Status:        reconciler.StatusPending(),
		StartedAt:     time.Time{},
		StoppedAt:     time.Time{},
		StartDuration: 0,
	}
}

func newDynamicFeatureTable(p tableParams) (statedb.RWTable[*DynamicFeature], error) {
	tbl, err := statedb.NewTable(
		TableName,
		featureIndex,
	)
	if err != nil {
		return nil, err
	}

	if err := p.DB.RegisterTable(tbl); err != nil {
		return tbl, err
	}

	if err := initializeTable(p, tbl); err != nil {
		return nil, err
	}

	return tbl, nil
}

func initializeTable(p tableParams, tbl statedb.RWTable[*DynamicFeature]) error {
	if !p.ManagerConfig.EnableDynamicLifecycleManager || !p.DynamicConfigCellConfig.EnableDynamicConfig {
		return nil
	}

	wTxn := p.DB.WriteTxn(tbl)
	defer wTxn.Commit()
	for _, r := range p.FeatureRegistrations {
		tl := newDynamicFeature(r.Name, r.Deps, r.Lifecycle.Hooks)
		_, _, _ = tbl.Insert(wTxn, tl)
	}

	return nil
}
