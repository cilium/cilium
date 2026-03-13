// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/ip"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	groupprovider "github.com/cilium/cilium/pkg/policy/groups/provider"
)

const AnnoGroupJSON = "cilium.io/external-group"
const LabelGroupManaged = "cilium.io/external-group-controller"
const FieldManager = "cilium.io/external-group-controller"

// sync performs all synchronization work:
// - deletes any unneeded groups
// - creates any new groups
// - refreshes any existing groups that are past their deadline
func (gc *externalGroupController) sync(ctx context.Context) error {
	// on first start, load existing CCGs from the apiserver.
	if gc.existing == nil {
		if err := gc.loadGroups(ctx); err != nil {
			return fmt.Errorf("failed to load existing groups: %w", err)
		}
	}

	// wait for upstream resources to synchronize.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gc.ready:
	}

	// determine set of groups pending synchronization
	toSync := gc.groupsToSync()
	errs := []error{}
	failed := sets.Set[groupKey]{}

	gc.log.Info("Synchronizing policy Groups to CiliumCIDRGroups",
		logfields.Count, len(toSync))

	for key, group := range toSync {
		var err error
		if group == nil {
			err = gc.removeGroup(ctx, key)
		} else {
			err = gc.ensureGroup(ctx, key, group)
		}

		if err != nil {
			gc.log.Warn("Failed to synchronize group (will retry)",
				logfields.Group, key)
			failed.Insert(key)
			errs = append(errs, err)
		}
	}

	// Re-enqueue any failed items
	if failed.Len() > 0 {
		gc.lock.Lock()
		gc.toUpdate.Insert(failed.UnsortedList()...)
		gc.lock.Unlock()
	}

	return errors.Join(errs...)
}

// groupsToSync determines the set of groups that need to be resynced:
// - new groups
// - deleted groups
// - groups past their update deadline
// returns a map of key to group; if group is nil, the corresponding CCG should be deleted.
func (gc *externalGroupController) groupsToSync() map[groupKey]*api.Groups {
	gc.lock.Lock()
	defer gc.lock.Unlock()
	startTime := time.Now()

	toSync := make(map[groupKey]*api.Groups, gc.toUpdate.Len())

	// All groups queued for update from network policy updates
	for key := range gc.toUpdate {
		toSync[key] = gc.groups[key]
	}
	gc.toUpdate = make(sets.Set[groupKey])

	// find all existing CCGs that reference missing groups
	for key, ccg := range gc.existing {
		if _, want := gc.groups[key]; !want {
			gc.log.Info("found stale CiliumCIDRGroup for Group",
				logfields.Group, key,
				logfields.Name, ccg.Name)
			toSync[key] = nil
		}
	}

	// Determine groups past the resync deadline
	for key, deadline := range gc.nextRefresh {
		if deadline.Before(startTime) {
			toSync[key] = gc.groups[key]
		}
	}

	return toSync
}

// ensureGroup resolves the IP addresses ferenced by the external group
// and applies them to a CiliumCIDRGroup.
//
// Note that we use the GenerateName feature, since we don't have a good key
// to use for the group name. Instead, we label the CCG with a hash of the
// external Group content's. We can use this label to correlate existing CCGs with
// desired groups.
func (gc *externalGroupController) ensureGroup(ctx context.Context, key groupKey, group *api.Groups) error {
	// short-cut if the group already exists and is not due for a resync.
	existing := gc.existing[key]
	if existing != nil && gc.nextRefresh[key].Before(time.Now()) {
		gc.log.Debug("Group already exists, skipping",
			logfields.Group, key,
			logfields.Name, existing.Name,
		)
		return nil
	}
	scopedLog := gc.log.With(logfields.Group, key)
	if existing != nil {
		scopedLog = scopedLog.With(logfields.Name, existing.Name)
	}

	scopedLog.Info("Creating or refreshing external group")

	// look up CIDRs from the actual external providers
	addrs, err := groupprovider.GetCidrSet(ctx, group)
	if err != nil {
		scopedLog.Warn("failed to lookup IPs for group (will retry)",
			logfields.Error, err)
		return err
	}

	// Check to see if the existing groups matches the set of IPs. If so,
	// we are complete.
	ccg := makeGroup(group, addrs)
	if existing != nil && existing.Spec.DeepEqual(&ccg.Spec) {
		scopedLog.Info("CiliumCIDRGroup for external Group is unchanged; skipping")
		gc.nextRefresh[key] = time.Now().Add(ResyncInterval)
		return nil
	}

	// At this point, we either need to create or update IPs
	// If creating, the APIServer will assign a unique name to the CCG.
	if existing == nil {
		created, err := gc.clientset.CiliumV2().CiliumCIDRGroups().Create(ctx, ccg, metav1.CreateOptions{FieldManager: FieldManager})
		if err != nil {
			scopedLog.Warn("Failed to create CiliumCIDRGroup for external Group",
				logfields.Error, err)
			return fmt.Errorf("failed to create CiliumCIDRGroup: %w", err)
		}
		scopedLog = scopedLog.With(logfields.Name, created.Name)
		gc.existing[key] = created
		scopedLog.Info("Created CiliumCIDRGroup for external Group",
			logfields.IPAddrs, addrs)

	} else {
		ccg.Name = existing.Name
		updated, err := gc.clientset.CiliumV2().CiliumCIDRGroups().Update(ctx, ccg, metav1.UpdateOptions{FieldManager: FieldManager})
		if err != nil {
			scopedLog.Warn("Failed to update CiliumCIDRGroup for external Group",
				logfields.Error, err)
			return fmt.Errorf("failed to update CiliumCIDRGroup %s: %w", ccg.Name, err)
		}
		scopedLog.Info("Update CiliumCIDRGroup with new IPs",
			logfields.IPAddrs, addrs)
		gc.existing[key] = updated
	}

	// Set the next refresh deadline
	gc.nextRefresh[key] = time.Now().Add(ResyncInterval)
	return nil
}

func (gc *externalGroupController) removeGroup(ctx context.Context, key groupKey) error {
	existing := gc.existing[key]
	if existing == nil {
		return nil
	}

	scopedLog := gc.log.With(
		logfields.Group, key,
		logfields.Name, existing.Name)

	err := gc.clientset.CiliumV2().CiliumCIDRGroups().Delete(ctx, existing.Name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		scopedLog.Warn("Failed to delete stale CiliumCIDRGroup for external Group",
			logfields.Error, err)
		return fmt.Errorf("failed to delete CiliumCIDRGroup %s: %w", existing.Name, err)
	}
	scopedLog.Info("Deleted stale CiliumCIDRGroup for external Group")

	delete(gc.existing, key)
	delete(gc.nextRefresh, key)

	return nil
}

func (gc *externalGroupController) loadGroups(ctx context.Context) error {
	store, err := gc.ccgResource.Store(ctx)
	if err != nil {
		return err
	}
	ccgs := store.List()

	existing := make(map[groupKey]*cilium_v2.CiliumCIDRGroup, len(ccgs))
	for _, ccg := range store.List() {
		if _, ok := ccg.Labels[LabelGroupManaged]; !ok {
			continue
		}
		keys := keysFromGroupLabel(ccg.Labels)
		if len(keys) != 1 {
			gc.log.Warn("detected CiliumCIDRGroup managed by Group controller with missing or duplicate key label; deleting!",
				logfields.Name, ccg.Name)

			err := gc.clientset.CiliumV2().CiliumCIDRGroups().Delete(ctx, ccg.Name, metav1.DeleteOptions{})
			if err != nil {
				gc.log.Warn("failed to delete invalid Group-managed CiliumCIDRGroup",
					logfields.Error, err,
					logfields.Name, ccg.Name)
			}
			continue
		}

		gc.log.Debug("found existing CiliumCIDRGroup",
			logfields.Name, ccg.Name,
			logfields.Group, keys[0])

		existing[keys[0]] = ccg
	}

	gc.existing = existing
	return nil
}

// keysFromGroupLabel looks for all labels with the group key prefix
// and determines the set of labels.
func keysFromGroupLabel(labels map[string]string) []groupKey {
	out := []groupKey{}
	for k := range labels {
		key, found := strings.CutPrefix(k, api.LabelGroupKeyPrefix)
		if !found || key == "" {
			continue
		}

		out = append(out, groupKey(key))
	}
	return out
}

// makeGroup creates the group object.
// existingName may be empty
func makeGroup(group *api.Groups, addrs []netip.Addr) *cilium_v2.CiliumCIDRGroup {
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
	b, _ := json.Marshal(group)

	return &cilium_v2.CiliumCIDRGroup{
		ObjectMeta: metav1.ObjectMeta{
			// Have the k8s apiserver generate the name for us
			GenerateName: "extgroup-to-cidrgroup-",

			// Annotate with group for debugging
			Annotations: map[string]string{
				AnnoGroupJSON: string(b),
			},

			// Label this as managed by the group operator
			Labels: map[string]string{
				LabelGroupManaged:           "",
				"app.kubernetes.io/part-of": "cilium",
				group.LabelKey():            "",
			},
		},
		Spec: cilium_v2.CiliumCIDRGroupSpec{
			ExternalCIDRs: cidrs,
		},
	}
}
