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
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/wal"
)

func registerReconciler(
	params reconciler.Params,
	lc cell.Lifecycle,
	tbl statedb.RWTable[*DesiredDevice],
	log *slog.Logger,
	config *option.DaemonConfig,
) (reconciler.Reconciler[*DesiredDevice], error) {
	ops := newOps(lc, params.DB, tbl, log, config)
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
	db   *statedb.DB
	tbl  statedb.Table[*DesiredDevice]
	log  *slog.Logger
	conf *option.DaemonConfig

	handle        *netlink.Handle
	wal           *wal.Writer[*reconcilerEvent]
	persistedKeys set.Set[DesiredDeviceKey]
}

func newOps(
	lifecycle cell.Lifecycle,
	db *statedb.DB,
	tbl statedb.Table[*DesiredDevice],
	log *slog.Logger,
	conf *option.DaemonConfig,
) *ops {
	ops := &ops{
		db:   db,
		tbl:  tbl,
		log:  log,
		conf: conf,

		persistedKeys: set.NewSet[DesiredDeviceKey](),
	}

	lifecycle.Append(cell.Hook{
		OnStart: ops.start,
		OnStop:  ops.stop,
	})

	return ops
}

func (ops *ops) start(_ cell.HookContext) error {
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

func (ops *ops) stop(_ cell.HookContext) error {
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
	nl, err := obj.DeviceSpec.ToNetlink()
	if err != nil {
		return fmt.Errorf("failed to translate to netlink link: %w", err)
	}

	// write to WAL first
	err = ops.wal.Write(&reconcilerEvent{
		Deleted: false,
		Key:     obj.GetOwnerlessKey(),
	})
	if err != nil {
		return fmt.Errorf("failed to write update event to WAL: %w", err)
	}

	err = ops.handle.LinkAdd(nl)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			err = ops.handle.LinkModify(nl)
			if err != nil {
				return fmt.Errorf("failed to modify link: %w", err)
			}
		} else {
			return fmt.Errorf("failed to add link: %w", err)
		}
	}

	return ops.handle.LinkSetUp(nl)
}

func (ops *ops) Delete(_ context.Context, txn statedb.ReadTxn, _ statedb.Revision, obj *DesiredDevice) error {
	nl, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return ops.handle.LinkByName(obj.Name)
	})
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}

	delErr := ops.handle.LinkDel(nl)

	err = ops.wal.Write(&reconcilerEvent{
		Deleted: true,
		Key:     obj.GetOwnerlessKey(),
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
		}
	}
	if ops.persistedKeys.Len() != 0 {
		ops.persistedKeys = set.NewSet[DesiredDeviceKey]()
	}

	return ops.wal.Compact(func(yield func(*reconcilerEvent) bool) {
		for obj := range objects {
			if obj.GetStatus().Kind == reconciler.StatusKindError {
				continue
			}

			if !yield(&reconcilerEvent{
				Deleted: false,
				Key:     obj.GetOwnerlessKey(),
			}) {
				return
			}
		}
	})
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
