// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package device

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/wal"
)

func registerReconciler(
	params reconciler.Params,
	lc cell.Lifecycle,
	tbl statedb.RWTable[*DesiredDevice],
	linuxDevices statedb.Table[*tables.Device],
	log *slog.Logger,
	config *option.DaemonConfig,
) (reconciler.Reconciler[*DesiredDevice], error) {
	ops := newOps(lc, params.DB, tbl, linuxDevices, log, config)
	rec, err := reconciler.Register(
		params,
		tbl,
		(*DesiredDevice).Clone,
		(*DesiredDevice).SetStatus,
		(*DesiredDevice).GetStatus,
		ops,
		nil,
		reconciler.WithPruning(30*time.Minute),
	)
	return rec, err
}

type ops struct {
	db           *statedb.DB
	tbl          statedb.Table[*DesiredDevice]
	linuxDevices statedb.Table[*tables.Device]
	log          *slog.Logger
	conf         *option.DaemonConfig

	handle        *netlink.Handle
	wal           *wal.Writer[*reconcilerEvent]
	persistedKeys set.Set[DesiredDeviceKey]
}

func newOps(
	lifecycle cell.Lifecycle,
	db *statedb.DB,
	tbl statedb.Table[*DesiredDevice],
	linuxDevices statedb.Table[*tables.Device],
	log *slog.Logger,
	conf *option.DaemonConfig,
) *ops {
	ops := &ops{
		db:           db,
		tbl:          tbl,
		linuxDevices: linuxDevices,
		log:          log,
		conf:         conf,

		persistedKeys: set.NewSet[DesiredDeviceKey](),
	}

	lifecycle.Append(ops)

	return ops
}

func (ops *ops) Start(_ cell.HookContext) error {
	var err error
	ops.handle, err = netlink.NewHandle()
	if err != nil {
		return err
	}

	walPath := filepath.Join(ops.conf.StateDir, "device-reconciler.wal")

	// Read all old device keys from the WAL.
	events, err := wal.Read(walPath, func(data []byte) (*reconcilerEvent, error) {
		var key reconcilerEvent
		if err := key.UnmarshalBinary(data); err != nil {
			return &reconcilerEvent{}, err
		}
		return &key, nil
	})
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		for oldDeviceKey, err := range events {
			if err != nil {
				ops.log.Error("Failed to read old device key from WAL", logfields.Error, err)
				continue
			}

			if oldDeviceKey.Deleted {
				ops.persistedKeys.Remove(oldDeviceKey.Key)
			} else {
				ops.persistedKeys.Insert(oldDeviceKey.Key)
			}
		}
	}

	ops.wal, err = wal.NewWriter[*reconcilerEvent](walPath)
	if err != nil {
		return err
	}

	return nil
}

func (ops *ops) Stop(_ cell.HookContext) error {
	if ops.handle != nil {
		_ = ops.handle.Close()
		ops.handle = nil
	}
	if ops.wal != nil {
		_ = ops.wal.Close()
	}
	return nil
}

func (ops *ops) Update(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, obj *DesiredDevice) error {
	nl, linkExist, err := ops.checkAndGetLink(obj)
	if err != nil {
		return err
	}

	// write to WAL first
	err = ops.wal.Write(&reconcilerEvent{
		Deleted: false,
		Key:     obj.GetKey(),
	})
	if err != nil {
		return fmt.Errorf("failed to write update event to WAL: %w", err)
	}

	if linkExist {
		err = ops.handle.LinkModify(nl)
	} else {
		err = ops.handle.LinkAdd(nl)
	}
	if err != nil {
		return fmt.Errorf("failed to add or modify link: %w", err)
	}

	ops.persistedKeys.Insert(obj.GetKey())

	return ops.handle.LinkSetUp(nl)
}

func (ops *ops) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, obj *DesiredDevice) error {
	nl, linkExist, err := ops.checkAndGetLink(obj)
	if err != nil {
		return err
	}

	if !linkExist {
		return nil
	}

	delErr := ops.handle.LinkDel(nl)
	if delErr == nil {
		ops.persistedKeys.Remove(obj.GetKey())
	}

	err = ops.wal.Write(&reconcilerEvent{
		Deleted: true,
		Key:     obj.GetKey(),
	})
	if err != nil {
		return fmt.Errorf("failed to write delete event to WAL: %w", err)
	}

	return delErr
}

func (ops *ops) Prune(_ context.Context, txn statedb.ReadTxn, objects iter.Seq2[*DesiredDevice, statedb.Revision]) error {
	for key := range ops.persistedKeys.Members() {
		_, _, found := ops.tbl.Get(txn, DesiredDeviceNameIndex.Query(key.Name))
		if !found {
			link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
				//nolint:forbidigo
				return ops.handle.LinkByName(key.Name)
			})
			// best effort cleanup of link which is present in WAL but missing in desired devices table.
			if err == nil {
				_ = ops.handle.LinkDel(link)
			}

			ops.persistedKeys.Remove(key)
		}
	}

	return ops.wal.Compact(func(yield func(*reconcilerEvent) bool) {
		for obj := range objects {
			if obj.GetStatus().Kind == reconciler.StatusKindError {
				continue
			}

			if !yield(&reconcilerEvent{
				Deleted: false,
				Key:     obj.GetKey(),
			}) {
				return
			}
		}
	})
}

// checkAndGetLink checks that the caller passing DesiredObject is not taking ownership of a device that is not owned by it.
// Few cases to consider
//  1. Device created by owner1. Owner2 tries to create device with same name. ( Not allowed )
//  2. Device already exist in kernel but not managed by Cilium ( persisted key does not exist ). Cilium owner tries
//     to create/delete a device with same name. ( Not allowed )
//  3. Device created by owner1. Cilium restart - Owner1 recreates the device ( allowed ). This case works as we
//     repopulate the persisted keys from the WAL.
func (ops *ops) checkAndGetLink(obj *DesiredDevice) (netlink.Link, bool, error) {
	nl, err := obj.DeviceSpec.ToNetlink()
	if err != nil {
		return nil, false, fmt.Errorf("failed to translate to netlink link: %w", err)
	}

	var linkExist bool
	_, err = safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return ops.handle.LinkByName(nl.Attrs().Name)
	})
	if err == nil || !errors.As(err, &netlink.LinkNotFoundError{}) {
		linkExist = true
	}

	if linkExist && !ops.persistedKeys.Has(obj.GetKey()) {
		return nil, false, fmt.Errorf("device %s exist in kernel but not with desired device owner %s", obj.Name, obj.Owner)
	}

	return nl, linkExist, nil
}

type reconcilerEvent struct {
	Deleted bool
	Key     DesiredDeviceKey
}

func (e *reconcilerEvent) MarshalBinary() ([]byte, error) {
	var buf []byte
	if e.Deleted {
		buf = append(buf, byte(1))
	} else {
		buf = append(buf, byte(0))
	}

	keyBuf, err := e.Key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = append(buf, keyBuf...)

	return buf, nil
}

func (e *reconcilerEvent) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("invalid event data: %v", data)
	}

	e.Deleted = data[0] == 1

	if err := e.Key.UnmarshalBinary(data[1:]); err != nil {
		return fmt.Errorf("invalid event data: %v", data)
	}

	return nil
}
