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
	ops := newOps(lc, tbl, log, config)
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
	tbl  statedb.Table[*DesiredDevice]
	log  *slog.Logger
	conf *option.DaemonConfig

	handle        *netlink.Handle
	wal           *wal.Writer[*reconcilerEvent]
	persistedKeys set.Set[DesiredDeviceKey]
}

func newOps(
	lifecycle cell.Lifecycle,
	tbl statedb.Table[*DesiredDevice],
	log *slog.Logger,
	conf *option.DaemonConfig,
) *ops {
	ops := &ops{
		tbl:  tbl,
		log:  log,
		conf: conf,

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
	nl, oldNl, err := ops.resolveOwnedLink(obj)
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

	if oldNl == nil {
		// Device does not exist yet — create it.
		err = ops.handle.LinkAdd(nl)
	} else if obj.DeviceSpec.NeedsRecreate(oldNl) {
		err = ops.handle.LinkDel(oldNl)
		if err == nil {
			err = ops.handle.LinkAdd(nl)
		}
	} else {
		err = ops.handle.LinkModify(nl)
	}
	if err != nil {
		return fmt.Errorf("failed to upsert link: %w", err)
	}

	ops.persistedKeys.Insert(obj.GetKey())

	return ops.handle.LinkSetUp(nl)
}

func (ops *ops) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, obj *DesiredDevice) error {
	_, oldNl, err := ops.resolveOwnedLink(obj)
	if err != nil {
		return err
	}

	if oldNl == nil {
		return nil
	}

	delErr := ops.handle.LinkDel(oldNl)
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

// resolveOwnedLink translates the desired device into its netlink form (nl) and
// looks up the matching link already present in the kernel, returning it as
// oldNl. A nil oldNl means the device does not exist yet and should be created;
// a non-nil oldNl is the live link to modify or recreate. Any netlink error
// other than "not found" is returned so the reconciler retries.
//
// When a device with that name already exists (non-nil oldNl) it must be owned by this owner,
// guarding against:
//  1. owner2 creating a device with a link already owned by owner1;
//  2. taking over a device present in the kernel but not managed by Cilium
//     (no persisted key for it).
//
// A link present in the kernel without a matching persisted key is therefore
// rejected. After a restart the persisted keys are repopulated from the WAL, so
// an owner re-creating its own device is allowed.
func (ops *ops) resolveOwnedLink(obj *DesiredDevice) (nl netlink.Link, oldNl netlink.Link, err error) {
	nl, err = obj.DeviceSpec.ToNetlink()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to translate to netlink link: %w", err)
	}

	oldNl, err = safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return ops.handle.LinkByName(nl.Attrs().Name)
	})
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nl, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to look up link %s: %w", nl.Attrs().Name, err)
	}

	if !ops.persistedKeys.Has(obj.GetKey()) {
		return nil, nil, fmt.Errorf("device %s exist in kernel but not with desired device owner %s", obj.Name, obj.Owner)
	}

	return nl, oldNl, nil
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
