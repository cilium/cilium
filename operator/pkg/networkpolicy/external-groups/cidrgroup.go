// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/statedb/part"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/ip"
	apiv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Functions for dealing with CiliumCIDRGroups

var gkCCG = schema.GroupKind{Group: cilium_v2.CustomResourceDefinitionGroup, Kind: cilium_v2.CCGKindDefinition}

const AnnoGroupJSON = "cilium.io/external-group"
const LabelGroupManaged = "cilium.io/external-group-controller"
const FieldManager = "cilium.io/external-group-controller"
const namePrefix = "auto-cilium-external-group-"

// handleCCGEvent updates the DB if a CiliumCIDRGroup was changed or deleted.
func (gm *externalGroupManager) handleCCGEvent(ctx context.Context, event resource.Event[*apiv2.CiliumCIDRGroup]) error {
	var err error
	defer func() {
		event.Done(err)
	}()

	if event.Kind == resource.Sync {
		// mark CiliumCIDRGroups as synced
		gm.ResourceKindSynced(gkCCG)
		return nil
	}

	// We only care about CCGs created by this controller
	if !strings.HasPrefix(event.Key.Name, namePrefix) {
		return nil
	}

	switch event.Kind {
	case resource.Delete:
		gm.onCCGDelete(event.Key.Name)
	case resource.Upsert:
		err = gm.onCCGUpdate(ctx, event.Object)
	}

	return nil
}

// onCCGDelete is called if a CCG managed by this controller is deleted.
// Remove the reference from the row (if it exists). It is likely that the
// table row is already gone.
func (gm *externalGroupManager) onCCGDelete(ccgName string) {
	wtxn := gm.db.WriteTxn(gm.tbl)
	defer wtxn.Abort()
	row, _, _ := gm.tbl.Get(wtxn, ExternalGroupByCCG(ccgName))

	if row == nil {
		// already deleted, nothing to do
		return
	}

	row = row.ShallowCopy()
	row.CCG = nil
	row.CCGName = ""

	_, _, err := gm.tbl.Insert(wtxn, row)
	if err != nil {
		// not reachable
		gm.log.Error("BUG: failed to update CCG from External Group table",
			logfields.Error, err)
		return
	}
	gm.log.Info("CCG for external Groups deleted, re-synchronizing",
		logfields.Name, ccgName,
		logfields.ID, row.ID)
	wtxn.Commit()

	// trigger sync, something is not right
	gm.trigger()
}

// onCCGUpdate is called when a CCG managed by this controller is first learned about,
// either on operator restart or when created by this controller. Update the corresponding
// row in the table, creating a stub one if necessary.
//
// Only returns error in a very remote corner case: a CCG is stale but deleting it failed.
func (gm *externalGroupManager) onCCGUpdate(ctx context.Context, ccg *apiv2.CiliumCIDRGroup) error {
	ccgName := ccg.Name

	// look up group ID from labels
	// If not present, this CCG is malformed; delete it.
	// (The name prefix means we own this CCG regardless).
	id := idFromLabels(ccg)
	if id == "" {
		gm.log.Warn("CiliumCIDRGroup missing ID label, deleting",
			logfields.Name, ccgName)
		return gm.deleteCCG(ctx, ccgName)
	}

	wtxn := gm.db.WriteTxn(gm.tbl)
	defer wtxn.Abort()

	// Look up row by ID from label.
	// May not be nil if row was created by a policy observer
	row, _, _ := gm.tbl.Get(wtxn, ExternalGroupByID(id))
	if row != nil {
		// If this group already as a CCG with a different name, then we have duplicates.
		// Delete.
		if row.CCGName != "" && row.CCGName != ccgName {
			gm.log.Warn("found multiple CiliumCIDRGroups for same external group. Deleting",
				logfields.Group, id,
				logfields.Name, ccgName,
			)
			wtxn.Abort() // release the lock.
			return gm.deleteCCG(ctx, ccgName)
		}

		// If the row's CCG exactly matches this one, we are getting the update event
		// for the CCG we already created; nothing to do.
		if row.CCG != nil && row.CCG.ResourceVersion == ccg.ResourceVersion {
			return nil
		}

		// Otherwise, update the DB with this CCG-Group mapping.
		row = row.ShallowCopy()
		row.CCGName = ccg.Name
		row.CCG = ccg
	} else {
		// No row in the DB for this CCG's group; create a stub one.
		// Unless this CCG is stale, we will learn the external group
		// when all policy has synced.
		row = &ExternalGroup{
			ID:      id,
			Owners:  part.Set[Owner]{},
			CCG:     ccg,
			CCGName: ccg.Name,
			// NextRefresh should be zero so we force refresh
		}
	}

	gm.log.Debug("CCG for an external group was changed, updating DB",
		logfields.Name, ccgName)

	_, _, err := gm.tbl.Insert(wtxn, row)
	if err != nil {
		// not reachable
		gm.log.Error("BUG: failed to update CCG from External Group table",
			logfields.Error, err)
		return nil
	}
	wtxn.Commit()
	return nil
}

// upsertCCG creates or updates the CCG in the apiserver
func (gm *externalGroupManager) upsertCCG(ctx context.Context, row *ExternalGroup, addrs []netip.Addr) (*apiv2.CiliumCIDRGroup, error) {
	newCCG := makeGroup(row, addrs)
	if skipCCGUpdate(row.CCG, newCCG) {
		gm.log.Debug("skipping CCG update: unchanged",
			logfields.Name, newCCG.Name)
		return row.CCG, nil
	}
	var err error

	// push to apiservers
	if row.CCG == nil {
		newCCG, err = gm.createCCG(ctx, newCCG)
	} else {
		newCCG.Name = row.CCG.Name
		newCCG, err = gm.updateCCG(ctx, newCCG)
	}
	if err != nil {
		return nil, err
	}
	return newCCG, err
}

// createCCG creates a CiliumCIDRGroup in the apiserver.
func (gm *externalGroupManager) createCCG(ctx context.Context, ccg *apiv2.CiliumCIDRGroup) (*apiv2.CiliumCIDRGroup, error) {
	ccg, err := gm.clientset.CiliumV2().CiliumCIDRGroups().Create(ctx, ccg, metav1.CreateOptions{FieldManager: FieldManager})
	if err != nil {
		gm.log.Warn("Failed to create CiliumCIDRGroup for external Group",
			logfields.Error, err)
		return nil, fmt.Errorf("failed to create CiliumCIDRGroup %w", err)
	}
	gm.log.Info("Created CiliumCIDRGroup for external Group",
		logfields.Name, ccg.Name,
	)
	return ccg, nil
}

// updateCCG updates an existing CiliumCIDRGroup in the apisever.
// falls back to Create if the group does not exist for some reason.
func (gm *externalGroupManager) updateCCG(ctx context.Context, ccg *apiv2.CiliumCIDRGroup) (*apiv2.CiliumCIDRGroup, error) {
	ccg, err := gm.clientset.CiliumV2().CiliumCIDRGroups().Update(ctx, ccg, metav1.UpdateOptions{FieldManager: FieldManager})
	if apierrors.IsNotFound(err) {
		gm.log.Warn("CiliumCIDRGroup for external group was unexpectedly deleted",
			logfields.Name, ccg.Name)
		return gm.createCCG(ctx, ccg)
	}
	if err != nil {
		gm.log.Warn("Failed to update CiliumCIDRGroup for external Group",
			logfields.Name, ccg.Name,
			logfields.Error, err)
		return nil, fmt.Errorf("failed to update CiliumCIDRGroup %s: %w", ccg.Name, err)
	}
	gm.log.Info("Updated CiliumCIDRGroup for external Group",
		logfields.Name, ccg.Name,
	)
	return ccg, nil
}

func (gm *externalGroupManager) deleteCCG(ctx context.Context, name string) error {
	// Delete the underlying CCG
	err := gm.clientset.CiliumV2().CiliumCIDRGroups().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		gm.log.Warn("Failed to delete stale CiliumCIDRGroup for external Group",
			logfields.Name, name,
			logfields.Error, err)
		return fmt.Errorf("failed to delete CiliumCIDRGroup %s: %w", name, err)
	}
	gm.log.Info("Deleted stale CiliumCIDRGroup for external group",
		logfields.Name, name)
	return nil
}

// skipCCGUpdate returns true if old is equivalent to upd.
func skipCCGUpdate(old, upd *apiv2.CiliumCIDRGroup) bool {
	if old == nil {
		return false
	}
	// never created
	if old.ResourceVersion == "" {
		return false
	}

	// IPs must match
	if !old.Spec.DeepEqual(&upd.Spec) {
		return false
	}

	// Check that all annotations and labels are what we want
	for k, newval := range upd.Annotations {
		oldval, ok := old.Annotations[k]
		if !ok || oldval != newval {
			return false
		}
	}
	for k, newval := range upd.Labels {
		oldval, ok := old.Labels[k]
		if !ok || oldval != newval {
			return false
		}
	}
	return true
}

// makeGroup creates the desired group object.
func makeGroup(row *ExternalGroup, addrs []netip.Addr) *cilium_v2.CiliumCIDRGroup {
	ip.SortAddrList(addrs)

	cidrs := make([]api.CIDR, 0, len(addrs))
	for _, addr := range addrs {
		prefix := "128"
		if addr.Is4() {
			prefix = "32"
		}
		cidrs = append(cidrs, api.CIDR(fmt.Sprintf("%s/%s", addr.String(), prefix)))
	}

	// cannot fail; this was already hashed before.
	b, _ := json.Marshal(row.ExtGroup)

	return &cilium_v2.CiliumCIDRGroup{
		ObjectMeta: metav1.ObjectMeta{

			// Let the APIServer generate a name for us
			GenerateName: namePrefix,

			// Annotate with group for debugging
			Annotations: map[string]string{
				AnnoGroupJSON: string(b),
			},

			// Label this as managed by the group operator
			Labels: map[string]string{
				LabelGroupManaged:           "",
				"app.kubernetes.io/part-of": "cilium",
				row.ExtGroup.LabelKey():     "",
			},
		},
		Spec: cilium_v2.CiliumCIDRGroupSpec{
			ExternalCIDRs: cidrs,
		},
	}
}

// idFromLabels extracts the external group ID from the CCG
func idFromLabels(ccg *cilium_v2.CiliumCIDRGroup) string {
	if _, ok := ccg.Labels[LabelGroupManaged]; !ok {
		return ""
	}

	for label := range ccg.Labels {
		if id, ok := strings.CutPrefix(label, api.LabelGroupKeyPrefix); ok {
			return id
		}
	}
	return ""
}
