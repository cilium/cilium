// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package device

import (
	"errors"
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

var (
	ErrOwnerDoesNotExist = errors.New("owner does not exist")
)

// ManagerOperations is the interface for the desired device reconciler manager
type ManagerOperations interface {
	// UpsertDevice upserts a desired device into the desired device table.
	UpsertDevice(device DesiredDevice) error
	// UpsertDeviceWait upserts a desired device into the desired device table
	// and waits for the device to be reconciled.
	UpsertDeviceWait(device DesiredDevice, timeout time.Duration) error
	// DeleteDevice deletes a desired device from the desired device table.
	DeleteDevice(device DesiredDevice) error
	// GetOrRegisterOwner gets or registers an owner with the given name.
	GetOrRegisterOwner(name string) DeviceOwner
	// RemoveOwner removes an owner and associated devices with the given owner.
	RemoveOwner(owner DeviceOwner) error
	// RegisterInitializer registers an initializer with the given name and returns
	// the initializer to the caller.
	RegisterInitializer(name string) Initializer
	// FinalizeInitializer should be called by the caller with registered initializer
	// once callers initial sync is completed. Once all initializers are finalized,
	// the reconciler will start initial pruning.
	FinalizeInitializer(initializer Initializer)
}

type manager struct {
	db  *statedb.DB
	tbl statedb.RWTable[*DesiredDevice]

	owners lock.Map[string, DeviceOwner]
}

func newDeviceManager(db *statedb.DB, tbl statedb.RWTable[*DesiredDevice]) ManagerOperations {
	return &manager{
		db:  db,
		tbl: tbl,
	}
}

type Initializer struct {
	initialized func(statedb.WriteTxn)
}

func (m *manager) RegisterInitializer(name string) Initializer {
	txn := m.db.WriteTxn(m.tbl)
	defer txn.Commit()

	return Initializer{
		initialized: m.tbl.RegisterInitializer(txn, name),
	}
}

func (m *manager) FinalizeInitializer(initializer Initializer) {
	if initializer.initialized != nil {
		txn := m.db.WriteTxn(m.tbl)
		defer txn.Commit()
		initializer.initialized(txn)
	}
}

func (m *manager) GetOrRegisterOwner(name string) DeviceOwner {
	owner, _ := m.owners.LoadOrStore(name, DeviceOwner{
		Name: name,
	})
	return owner
}

func (m *manager) RemoveOwner(owner DeviceOwner) error {
	if _, exists := m.owners.Load(owner.Name); !exists {
		return ErrOwnerDoesNotExist
	}

	txn := m.db.WriteTxn(m.tbl)
	defer txn.Abort()

	for device := range m.tbl.Prefix(txn, DesiredDeviceIndex.Query(DesiredDeviceKey{
		Owner: owner,
	})) {
		if _, _, err := m.tbl.Delete(txn, device); err != nil {
			return err
		}
	}

	m.owners.Delete(owner.Name)
	txn.Commit()
	return nil
}

func (m *manager) UpsertDevice(device DesiredDevice) error {
	txn := m.db.WriteTxn(m.tbl)
	defer txn.Abort()

	if err := device.Validate(); err != nil {
		return err
	}

	if _, ok := m.owners.Load(device.Owner.Name); !ok {
		return ErrOwnerDoesNotExist
	}

	if oldObj, _, found := m.tbl.Get(txn, DesiredDeviceNameIndex.Query(device.Name)); found && oldObj.Owner != device.Owner {
		return fmt.Errorf("device %s exists with different owner %s", device.Name, oldObj.Owner.Name)
	}

	if _, _, err := m.tbl.Insert(txn, device.SetStatus(reconciler.StatusPending())); err != nil {
		return err
	}

	txn.Commit()
	return nil
}

func (m *manager) UpsertDeviceWait(device DesiredDevice, timeout time.Duration) error {
	err := m.UpsertDevice(device)
	if err != nil {
		return err
	}

	return m.waitForReconciliation(device.GetKey(), timeout)
}

func (m *manager) DeleteDevice(device DesiredDevice) error {
	txn := m.db.WriteTxn(m.tbl)
	defer txn.Abort()

	if err := device.Validate(); err != nil {
		return err
	}

	if _, ok := m.owners.Load(device.Owner.Name); !ok {
		return ErrOwnerDoesNotExist
	}

	if oldObj, _, found := m.tbl.Get(txn, DesiredDeviceNameIndex.Query(device.Name)); found && oldObj.Owner != device.Owner {
		return fmt.Errorf("device %s exists with different owner %s", device.Name, oldObj.Owner.Name)
	}

	if _, _, err := m.tbl.Delete(txn, &device); err != nil {
		return err
	}

	txn.Commit()
	return nil
}

func (m *manager) waitForReconciliation(deviceKey DesiredDeviceKey, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()

	var err error
	for {
		obj, _, watch, found := m.tbl.GetWatch(m.db.ReadTxn(), DesiredDeviceIndex.Query(deviceKey))
		if !found {
			return fmt.Errorf("device %s not found", deviceKey)
		}

		switch obj.status.Kind {
		case reconciler.StatusKindDone:
			return nil
		case reconciler.StatusKindError:
			err = errors.New(obj.status.GetError())
		}

		select {
		case <-t.C:
			return fmt.Errorf("timeout waiting for %s reconciliation: %w", deviceKey, err)
		case <-watch:
		}
	}
}
