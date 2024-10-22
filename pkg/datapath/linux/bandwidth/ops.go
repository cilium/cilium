// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"context"
	"fmt"
	"iter"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
)

type ops struct {
	log       *slog.Logger
	isEnabled func() bool
}

func newOps(log *slog.Logger, mgr types.BandwidthManager) reconciler.Operations[*tables.BandwidthQDisc] {
	return &ops{log, mgr.Enabled}
}

// Delete implements reconciler.Operations.
func (*ops) Delete(context.Context, statedb.ReadTxn, *tables.BandwidthQDisc) error {
	// We don't restore the original qdisc on delete.
	return nil
}

// Prune implements reconciler.Operations.
func (*ops) Prune(context.Context, statedb.ReadTxn, iter.Seq2[*tables.BandwidthQDisc, statedb.Revision]) error {
	// We don't touch qdiscs of other devices.
	return nil
}

// Update implements reconciler.Operations.
func (ops *ops) Update(ctx context.Context, txn statedb.ReadTxn, q *tables.BandwidthQDisc) error {
	if !ops.isEnabled() {
		// Probe results show that the system doesn't support BandwidthManager, so
		// bail out.
		return nil
	}

	link, err := netlink.LinkByIndex(q.LinkIndex)
	if err != nil {
		return fmt.Errorf("LinkByIndex: %w", err)
	}
	device := link.Attrs().Name

	// Check if the qdiscs are already set up as expected.
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("QdiscList: %w", err)
	}
	updatedQdiscs := 0
	// Update numEgressQdiscs to only include egress qdiscs while iterating
	numEgressQdiscs := len(qdiscs)
	for _, qdisc := range qdiscs {
		switch qdisc.Attrs().Parent {
		// Update egress qdisc count by excluding clsact and ingress qdiscs.
		// clsact and ingress have the same handle.
		case netlink.HANDLE_CLSACT:
			numEgressQdiscs--
		case netlink.HANDLE_ROOT:
			if qdisc.Type() == "mq" {
				updatedQdiscs++
			}
		default:
			if qdisc.Type() == "fq" {
				fq, _ := qdisc.(*netlink.Fq)

				// If it's "fq" and with our parameters, then assume this was
				// already set up and there wasn't any MQ support.
				ok := fq.Horizon == uint32(q.FqHorizon.Microseconds()) &&
					fq.Buckets == q.FqBuckets
				if ok {
					updatedQdiscs++
				}
			}

		}
	}
	if updatedQdiscs == numEgressQdiscs {
		return nil
	}

	// We strictly want to avoid a down/up cycle on the device at
	// runtime, so given we've changed the default qdisc to FQ, we
	// need to reset the root qdisc, and then set up MQ which will
	// automatically get FQ leaf qdiscs (given it's been default).
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "noqueue",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("cannot replace root Qdisc to %s on device %s: %w", qdisc.QdiscType, device, err)
	}
	qdisc = &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "mq",
	}
	which := "mq with fq leaves"
	if err := netlink.QdiscReplace(qdisc); err != nil {
		// No MQ support, so just replace to FQ directly.
		fq := &netlink.Fq{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_ROOT,
			},
			Pacing: 1,
		}
		// At this point there is nothing we can do about
		// it if we fail here, so hard bail out.
		if err = netlink.QdiscReplace(fq); err != nil {
			return fmt.Errorf("cannot replace root Qdisc to %s on device %s: %w", fq.Type(), device, err)
		}
		which = "fq"
	}
	ops.log.Info("Setting qdisc", "qdisc", which, "device", device)

	// Set the fq parameters
	qdiscs, err = netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("QdiscList: %w", err)
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "fq" {
			fq, _ := qdisc.(*netlink.Fq)
			fq.Horizon = uint32(FqDefaultHorizon.Microseconds())
			fq.Buckets = uint32(FqDefaultBuckets)
			if err := netlink.QdiscReplace(qdisc); err != nil {
				return fmt.Errorf("cannot set qdisc attributes: %w", err)
			}
		}
	}

	return nil
}

var _ reconciler.Operations[*tables.BandwidthQDisc] = &ops{}
