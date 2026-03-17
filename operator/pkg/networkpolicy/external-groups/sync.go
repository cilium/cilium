// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/hive/cell"

	groupprovider "github.com/cilium/cilium/operator/pkg/networkpolicy/external-groups/provider"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// sync performs all synchronization work:
// - deletes any unneeded groups
// - creates any new groups
// - refreshes any existing groups that are past their deadline
func (gm *externalGroupManager) sync(ctx context.Context, health cell.Health) error {
	// wait for upstream resources to synchronize.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gm.ready:
	}

	sleepInterval := 15 * time.Minute

	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-gm.trig:
		case <-time.After(sleepInterval):
		}

		var err error
		sleepInterval, err = gm.doSync(ctx)

		if err != nil {
			gm.log.Warn("Failed to synchronize External Groups to CiliumCIDRGroups, will retry",
				logfields.Error, err,
			)
			sleepInterval = 30 * time.Second
			health.Degraded("Not all CiliumCIDRGroups were synchronized", err)
		} else {
			health.OK("All CiliumCIDRGroups have been synchronized")
		}
	}

	return ctx.Err()
}

// doSync returns an approximate duration until the next sync
func (gm *externalGroupManager) doSync(ctx context.Context) (time.Duration, error) {

	// determine set of groups pending synchronization
	toSync, nextWake := gm.groupsToSync()
	if len(toSync) == 0 {
		return max(30*time.Second, time.Until(nextWake)), nil
	}

	gm.log.Info("Synchronizing policy Groups to CiliumCIDRGroups",
		logfields.Count, len(toSync))

	errs := []error{}
	// upsert or delete every group
	for _, group := range toSync {
		var err error
		if group.Owners.Len() == 0 {
			err = gm.removeGroup(ctx, group)
		} else {
			err = gm.ensureGroup(ctx, group)
		}

		if err != nil {
			gm.log.Warn("Failed to synchronize group (will retry)",
				logfields.Group, group.ID)
			errs = append(errs, err)
		}
	}

	// clamp deadline-based refresh to at most one per 30 seconds.
	sleepInterval := max(30*time.Second, time.Until(nextWake))
	return sleepInterval, errors.Join(errs...)
}

// groupsToSync determines the set of groups that need to be resynced:
// - new groups
// - deleted groups
// - groups past their update deadline
//
// Returns the set of groups to sync and the next pending deadline
func (gm *externalGroupManager) groupsToSync() ([]*ExternalGroup, time.Time) {
	out := []*ExternalGroup{}

	// Track the next wakeup time that is after now()
	nextWake := time.Now().Add(gm.cfg.ExternalGroupSyncInterval)

	rtx := gm.db.ReadTxn()
	for group := range gm.tbl.All(rtx) {
		switch {
		// deadline exceeded
		case group.NextRefresh.Before(time.Now()):
			fallthrough
		// stale group
		case group.Owners.Len() == 0:
			fallthrough
		// no CCG, new group
		case group.CCG == nil:
			out = append(out, group)
		// Group is not due for a refresh, but it is next:
		case group.NextRefresh.Before(nextWake):
			nextWake = group.NextRefresh
		}
	}
	return out, nextWake
}

// ensureGroup resolves the IP addresses referenced by the external group
// and applies them to a CiliumCIDRGroup, creating or updating as necessary
func (gm *externalGroupManager) ensureGroup(ctx context.Context, row *ExternalGroup) error {
	scopedLog := gm.log.With(
		logfields.Group, row.ID,
	)

	if row.ExtGroup == nil {
		// should be unreachable, unless there is a bug with stale CCGs
		gm.log.Error("BUG: ExternalGroup table with nil Group",
			logfields.Group, row.ID)
		return nil
	}

	scopedLog.Debug("Looking up IPs for external group")
	// look up CIDRs from the actual external providers
	addrs, err := groupprovider.GetCidrSet(ctx, row.ExtGroup)
	if err != nil {
		scopedLog.Warn("Failed to lookup IPs for external group (will retry)",
			logfields.Error, err)
		return err
	}

	// This will create or update the CCG in the apiserver.
	// it may short-cut.
	ccg, err := gm.upsertCCG(ctx, row, addrs)
	if err != nil {
		return err
	}

	// update CCG in table and bump refresh time
	wtx := gm.db.WriteTxn(gm.tbl)
	defer wtx.Abort()

	row, _, found := gm.tbl.Get(wtx, ExternalGroupByID(row.ID))
	if !found {
		gm.log.Error("BUG: group deleted while trying to write")
		return nil
	}

	// set CCG and new deadline
	row = row.ShallowCopy()
	row.CCG = ccg
	row.CCGName = ccg.Name
	row.NextRefresh = time.Now().Add(gm.cfg.ExternalGroupSyncInterval)

	_, _, err = gm.tbl.Insert(wtx, row)
	if err != nil {
		// unreachable
		gm.log.Error("BUG: failed to update External Group",
			logfields.Error, err)
	}
	wtx.Commit()
	return nil
}

// removeGroup removes a row and, if relevant, its CCG.
func (gm *externalGroupManager) removeGroup(ctx context.Context, row *ExternalGroup) error {
	scopedLog := gm.log.With(
		logfields.Group, row.ID,
		logfields.Name, namePrefix+row.ID,
	)

	wtxn := gm.db.WriteTxn(gm.tbl)
	defer wtxn.Abort()

	// refresh the group, it may have changed
	row, _, found := gm.tbl.Get(wtxn, ExternalGroupByID(row.ID))
	if !found {
		return nil
	}

	// New owner, group no longer stale.
	if row.Owners.Len() != 0 {
		return nil
	}

	if row.CCG != nil {
		// Delete the underlying CCG
		err := gm.clientset.CiliumV2().CiliumCIDRGroups().Delete(ctx, row.CCG.Name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			scopedLog.Warn("Failed to delete stale CiliumCIDRGroup for external Group",
				logfields.Error, err)
			return fmt.Errorf("failed to delete CiliumCIDRGroup %s: %w", row.CCG.Name, err)
		}
		scopedLog.Info("Deleted stale CiliumCIDRGroup for external Group")
	}

	// Remove group from DB
	_, _, err := gm.tbl.Delete(wtxn, row)
	if err != nil {
		gm.log.Error("BUG: failed to delete ExternalGroup row",
			logfields.Error, err,
		)
	}
	wtxn.Commit()

	return nil
}
