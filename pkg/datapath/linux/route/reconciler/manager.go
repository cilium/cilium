// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

type DesiredRouteManager struct {
	db  *statedb.DB
	tbl statedb.RWTable[*DesiredRoute]

	mu     lock.Mutex
	owners map[string]*RouteOwner
}

func newDesiredRouteManager(
	db *statedb.DB,
	tbl statedb.RWTable[*DesiredRoute],
	// Add reconciler as a dependency to ensure it's constructed and started
	// before the manager is used by other components (e.g., loader, proxy).
	// This guarantees the reconciler's jobs are registered with the job group.
	_ reconciler.Reconciler[*DesiredRoute],
) *DesiredRouteManager {
	return &DesiredRouteManager{
		db:     db,
		tbl:    tbl,
		owners: make(map[string]*RouteOwner),
	}
}

var (
	ErrOwnerExists       = errors.New("owner already exists")
	ErrOwnerDoesNotExist = errors.New("owner does not exist")
)

func (m *DesiredRouteManager) RegisterOwner(name string) (*RouteOwner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.owners[name]; exists {
		return nil, ErrOwnerExists
	}

	return m.newOwner(name), nil
}

func (m *DesiredRouteManager) GetOrRegisterOwner(name string) (*RouteOwner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if owner, exists := m.owners[name]; exists {
		return owner, nil
	}

	return m.newOwner(name), nil
}

// must be called with m.mu held
func (m *DesiredRouteManager) newOwner(name string) *RouteOwner {
	owner := &RouteOwner{
		name: name,
	}

	m.owners[name] = owner
	return owner
}

func (m *DesiredRouteManager) GetOwner(name string) (*RouteOwner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	owner, exists := m.owners[name]
	if !exists {
		return nil, ErrOwnerDoesNotExist
	}
	return owner, nil
}

func (m *DesiredRouteManager) RemoveOwner(owner *RouteOwner) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.owners[owner.name]; !exists {
		return ErrOwnerDoesNotExist
	}
	delete(m.owners, owner.name)

	txn := m.db.WriteTxn(m.tbl)
	defer txn.Abort()

	for route := range m.tbl.Prefix(txn, DesiredRouteIndex.Query(DesiredRouteKey{
		Owner: owner,
	})) {
		if _, _, err := m.tbl.Delete(txn, route); err != nil {
			return err
		}

		if err := m.selectRoutes(txn, route.GetOwnerlessKey()); err != nil {
			return err
		}
	}

	txn.Commit()
	return nil
}

type Initializer struct {
	initialized func(statedb.WriteTxn)
}

func (m *DesiredRouteManager) RegisterInitializer(name string) Initializer {
	txn := m.db.WriteTxn(m.tbl)
	defer txn.Commit()

	return Initializer{
		initialized: m.tbl.RegisterInitializer(txn, name),
	}
}

func (m *DesiredRouteManager) FinalizeInitializer(initializer Initializer) {
	if initializer.initialized != nil {
		txn := m.db.WriteTxn(m.tbl)
		defer txn.Commit()
		initializer.initialized(txn)
	}
}

func (m *DesiredRouteManager) UpsertRoute(route DesiredRoute) error {
	txn := m.db.WriteTxn(m.tbl)
	defer txn.Abort()

	if err := route.ValidateAndSetDefaults(); err != nil {
		return err
	}

	// By default, any new route we add is not selected and does not have to be reconciled.
	// The [selectRoutes] method will select the best route for each prefix+table.
	route.selected = false
	route.SetStatus(reconciler.StatusDone())

	if _, _, err := m.tbl.Insert(txn, &route); err != nil {
		return err
	}

	if err := m.selectRoutes(txn, route.GetOwnerlessKey()); err != nil {
		return err
	}

	txn.Commit()
	return nil
}

func (m *DesiredRouteManager) UpsertRouteWait(route DesiredRoute) error {
	if err := m.UpsertRoute(route); err != nil {
		return err
	}

	return m.waitForReconciliation(route.GetFullKey())
}

func (m *DesiredRouteManager) DeleteRoute(route DesiredRoute) error {
	txn := m.db.WriteTxn(m.tbl)
	defer txn.Abort()

	if err := route.ValidateAndSetDefaults(); err != nil {
		return err
	}

	if _, _, err := m.tbl.Delete(txn, &route); err != nil {
		return err
	}

	if err := m.selectRoutes(txn, route.GetOwnerlessKey()); err != nil {
		return err
	}

	txn.Commit()
	return nil
}

const reconciliationTimeout = 1 * time.Second

func (m *DesiredRouteManager) waitForReconciliation(routeKey DesiredRouteKey) error {
	t := time.NewTimer(reconciliationTimeout)
	defer t.Stop()

	var err error
	for {
		obj, _, watch, found := m.tbl.GetWatch(m.db.ReadTxn(), DesiredRouteIndex.Query(routeKey))
		if !found {
			return fmt.Errorf("route %s not found", routeKey)
		}

		if obj.status.Kind == reconciler.StatusKindDone {
			// already reconciled
			return nil
		}

		select {
		case <-t.C:
			if err != nil {
				return fmt.Errorf("timeout waiting for parameter %s reconciliation: %w", routeKey, err)
			}
			return fmt.Errorf("timeout waiting for parameter %s reconciliation", routeKey)
		case <-watch:
			if obj.status.Kind == reconciler.StatusKindDone {
				return nil
			}
			if obj.status.Kind == reconciler.StatusKindError {
				err = errors.New(obj.status.GetError())
			}
		}
	}
}

func (m *DesiredRouteManager) selectRoutes(txn statedb.WriteTxn, key DesiredRouteKey) error {
	// Get all routes with the same prefix and table.
	routes := slices.Collect(statedb.ToSeq(m.tbl.List(txn, DesiredRouteTablePrefixIndex.Query(key))))
	if len(routes) == 0 {
		return nil // nothing to select
	}

	// Sort routes by admin distance and name, so that the first one is the
	// one that is selected.
	slices.SortStableFunc(routes, func(a, b *DesiredRoute) int {
		adminDiff := int(a.AdminDistance) - int(b.AdminDistance)
		if adminDiff == 0 {
			if a.Owner.name < b.Owner.name {
				return -1
			}
			if a.Owner.name > b.Owner.name {
				return 1
			}
		}

		return adminDiff
	})

	// Mark first route as selected, and all others as not selected.
	for i, route := range routes {
		selected := i == 0
		if selected == route.selected {
			continue
		}

		changed := route.SetStatus(reconciler.StatusPending())
		changed.selected = selected
		if _, _, err := m.tbl.Insert(txn, changed); err != nil {
			return err
		}
	}

	return nil
}
