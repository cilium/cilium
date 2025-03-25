// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"context"
	"iter"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/agent"
	monitorapi "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type PolicyImporter interface {
	UpdatePolicy(*policytypes.PolicyUpdate)
}

type policyImporterParams struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group
	Config   Config

	Repo            policy.PolicyRepository
	EndpointManager endpointmanager.EndpointManager
	IPCache         *ipcache.IPCache
	MonitorAgent    agent.Agent
}

type policyImporter struct {
	log          *slog.Logger
	repo         policy.PolicyRepository
	epm          epmanager
	ipc          ipcacher
	monitorAgent agent.Agent

	// prefixesByResources is the list of prefixes
	// that belong to each resource. This is tracked separately
	// so we can allocate and release prefixes as policy changes.
	prefixesByResource map[ipcachetypes.ResourceID][]netip.Prefix

	q chan *policytypes.PolicyUpdate
}

type ipcacher interface {
	UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64)
	RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64)
	WaitForRevision(ctx context.Context, rev uint64) error
}

type epmanager interface {
	UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64)
}

func newPolicyImporter(cfg policyImporterParams) PolicyImporter {
	i := &policyImporter{
		log:          cfg.Log,
		repo:         cfg.Repo,
		epm:          cfg.EndpointManager,
		ipc:          cfg.IPCache,
		monitorAgent: cfg.MonitorAgent,

		q: make(chan *policytypes.PolicyUpdate, cfg.Config.PolicyQueueSize),

		prefixesByResource: map[ipcachetypes.ResourceID][]netip.Prefix{},
	}

	buf := stream.Buffer(
		stream.FromChannel(i.q),
		int(cfg.Config.PolicyQueueSize), 10*time.Millisecond,
		concat)

	cfg.JobGroup.Add(job.Observer("policy-importer", i.processUpdates, buf))

	return i
}

// ResourceIDAnonymous is the anonymous ipcache resource used as a placeholder
// for policies that allocate CIDRs but do not have an owning resource.
// (This is only used for policies created by the local API).
const ResourceIDAnonymous = "policy/anonymous"

func (i *policyImporter) UpdatePolicy(u *policytypes.PolicyUpdate) {
	i.q <- u
}

func concat(buf []*policytypes.PolicyUpdate, in *policytypes.PolicyUpdate) []*policytypes.PolicyUpdate {
	buf = append(buf, in)
	return buf
}

// updatePrefixes determines the set of prefixes "owned" by a given resource and applies them
// to the ipcache.
// Write lock must be held.
//
// If the ipcache has started, it waits up to a configurable deadline for the prefixes
// to be allocated.
//
// It returns the set of stale prefixes that should be deallocated after policy updates are complete.
func (i *policyImporter) updatePrefixes(ctx context.Context, updates []*policytypes.PolicyUpdate) (toPrune map[ipcachetypes.ResourceID][]netip.Prefix) {
	if i.ipc == nil {
		return
	}

	// The set of all prefixes that belong to a resource.
	toAllocate := map[ipcachetypes.ResourceID][]netip.Prefix{}
	prefixSource := map[ipcachetypes.ResourceID]source.Source{}
	toPrune = map[ipcachetypes.ResourceID][]netip.Prefix{}

	// First, gather all new prefixes and index them by resource.
	//
	// For rules without an owning resource (i.e. created by local REST API),
	// we never de-allocate prefixes. Otherwise, we will track prefixes
	// by resource and de-allocate unused prefixes after policy is applied.
	for _, upd := range updates {
		prefixes := policy.GetCIDRPrefixes(upd.Rules)
		if upd.Resource == "" {
			// edge-case: no owning resource.
			// Allocate prefixes with a placeholder.
			if len(prefixes) == 0 {
				continue
			}
			// since anonymous prefixes may come from multiple sources,
			// we append to the list
			toAllocate[ResourceIDAnonymous] = append(toAllocate[ResourceIDAnonymous], prefixes...)
			prefixSource[ResourceIDAnonymous] = upd.Source // This could overwrite if there are multiple sources, but in practice there aren't

		} else {
			// Standard case: there is an owning resource.
			// Track the complete set of per-prefix resources.
			// We want empty sets here!
			toAllocate[upd.Resource] = prefixes
			prefixSource[upd.Resource] = upd.Source
		}
	}

	// Now that we know the exact set of prefixes for each resource, determine ipcache update.
	// Note that we did this step separately, as we could have batched multiple updates
	// for the same resource (i.e A1, A2, A3 -> only A3 matters)
	//
	// We elide updates when the prefix already has an entry for the given resource.
	var ipcUpdates []ipcache.MU
	for resource, newPrefixes := range toAllocate {
		// For anonymous prefixes, just allocate, don't bookkeep
		if resource == ResourceIDAnonymous {
			for _, prefix := range newPrefixes {
				ipcUpdates = append(ipcUpdates, ipcache.MU{
					Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
					Source:   prefixSource[resource],
					Resource: resource,
					Metadata: []ipcache.IPMetadata{labels.GetCIDRLabels(prefix)},
					IsCIDR:   true,
				})
			}
			continue
		}

		// otherwise, update bookkeeping and determine diff
		oldPrefixes := i.prefixesByResource[resource]

		// No prefixes for this resource: clear entry, prune all old prefixes.
		if len(newPrefixes) == 0 {
			delete(i.prefixesByResource, resource)
			if len(oldPrefixes) > 0 {
				toPrune[resource] = oldPrefixes
				continue
			}
		}

		// Otherwise, update bookkeeping, upsert any net-new prefixes.
		i.prefixesByResource[resource] = newPrefixes
		oldSet := set.NewSet(oldPrefixes...)
		for _, prefix := range newPrefixes {
			// If we already allocated this prefix, remove it from the prune list
			// and don't bother upserting it again in to the ipcache
			if oldSet.Remove(prefix) {
				continue
			}

			ipcUpdates = append(ipcUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
				Source:   prefixSource[resource],
				Resource: resource,
				Metadata: []ipcache.IPMetadata{labels.GetCIDRLabels(prefix)},
				IsCIDR:   true,
			})
		}
		if oldSet.Len() > 0 {
			toPrune[resource] = oldSet.AsSlice()
		}
	}

	// Batch the set of updates to the ipcache.
	if len(ipcUpdates) > 0 {
		i.log.Info("inserting ipcache metadata for CIDR prefixes from policy", logfields.Count, len(ipcUpdates))
		nextIPCRev := i.ipc.UpsertMetadataBatch(ipcUpdates...)

		// If the ipcache has already started, then we should wait for our update to commit.
		// However, no sense in waiting if the agent is still starting up.
		// For resilience purposes, we will wait a maximum of 10 seconds for the ipcache to make progress.
		if nextIPCRev > 1 {
			i.log.Debug("Waiting up to 10 seconds for ipcache to upsert policy prefix metadata")
			updCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := i.ipc.WaitForRevision(updCtx, nextIPCRev); err != nil {
				i.log.Warn("Timed out waiting for ipcache to allocate identities for prefixes while consuming policy updates. This may cause policy drops!")
			}
			cancel()
		} else {
			i.log.Debug("Agent is starting up, not waiting for ipcache while importing policy")
		}
	}

	return toPrune
}

// prunePrefixes removes the CIDR labels from the given set of (resource, prefix) pairs.
func (i *policyImporter) prunePrefixes(prunePrefixes map[ipcachetypes.ResourceID][]netip.Prefix) {
	if i.ipc == nil {
		return
	}
	var ipcUpdates []ipcache.MU
	for resource, oldPrefixes := range prunePrefixes {
		// Prune all stale prefixes
		for _, oldPrefix := range oldPrefixes {
			ipcUpdates = append(ipcUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(oldPrefix),
				Resource: resource,
				Metadata: []ipcache.IPMetadata{labels.Labels{}},
				IsCIDR:   true,
			})
		}
	}
	if len(ipcUpdates) > 0 {
		i.log.Info("pruning stale policy CIDR prefix ipcache metadata entries", logfields.Count, len(ipcUpdates))
		// No need to wait for completion.
		i.ipc.RemoveMetadataBatch(ipcUpdates...)
	}
}

// processUpdates takes a set of one or more policy updates and applies them to
// the repository. It then regenerates or skips revisions of endpoints as necessary.
//
// It also handles prefix allocation in the ipcache when the supplied rules rely on
// CIDR identities.
// (Does not actually return error, just to satisfy the Job signature)
func (i *policyImporter) processUpdates(ctx context.Context, updates []*policytypes.PolicyUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	i.log.Info("Processing policy updates", logfields.Count, len(updates))

	// First, allocate local identities for all prefixes referenced by policies.
	//
	// This must happen before the policies are applied to the endpoints. Doing
	// so prevents traffic from being dropped. Consider a policy that allows
	// access to 1.1.1.1/32. It only allows traffic to identities that match that selector.
	// If we were to apply the policy to the endpoint before allocating an identity for
	// that prefix, traffic to 1.1.1.1/32 may have the world identity, which would be dropped.
	//
	// So, we must always perform identity allocation first, then update policy.
	// The ony exception is if we are starting up, in which case we may proceed.
	oldPrefixes := i.updatePrefixes(ctx, updates)

	// Apply changes to the repository.
	//
	// As we commit to the policy repository, we must also determine the set of identities
	// to regenerate here. Identities selected by either outgoing or incoming rules
	// will have to be regenerated.
	idsToRegen := &set.Set[identity.NumericIdentity]{}
	startRevision := i.repo.GetRevision()
	endRevision := startRevision
	var oldRuleCnt int
	for _, upd := range updates {
		var regen *set.Set[identity.NumericIdentity]

		// The standard case: we have an owning resource, either a k8s object
		// or a file on disk.
		if upd.Resource != "" {
			regen, endRevision, oldRuleCnt = i.repo.ReplaceByResource(upd.Rules, upd.Resource)
		} else {
			// otherwise, this is a local API call, and we are replacing by labels.
			// Compute the set of sets of labels to replace.
			var replaceLabels []labels.LabelArray
			if upd.ReplaceByLabels {
				for _, rule := range upd.Rules {
					replaceLabels = append(replaceLabels, rule.Labels)
				}
			}
			if len(upd.ReplaceWithLabels) > 0 {
				replaceLabels = append(replaceLabels, upd.ReplaceWithLabels)
			}

			if len(upd.Rules) == 0 && len(replaceLabels) == 0 {
				// No rules, no resource, no labels. This means we should clear all policies.
				// Add an empty label selector
				i.log.Info("Policy replace request with no labels, deleting all policies!")
				replaceLabels = append(replaceLabels, labels.LabelArray{})
			}

			if len(replaceLabels) >= 0 {
				i.log.Info("Replacing policy by labels",
					logfields.Labels, replaceLabels,
					logfields.Count, len(upd.Rules),
				)
			}
			regen, endRevision, oldRuleCnt = i.repo.ReplaceByLabels(upd.Rules, replaceLabels)
		}

		if len(upd.Rules) == 0 {
			i.log.Info("Deleted policy from repository",
				logfields.Resource, upd.Resource,
				logfields.PolicyRevision, endRevision,
				logfields.DeletedRules, oldRuleCnt,
				logfields.Identity, slices.Collect(truncate(regen.Members(), 100)))
		} else {
			i.log.Info("Upserted policy to repository",
				logfields.Resource, upd.Resource,
				logfields.PolicyRevision, endRevision,
				logfields.DeletedRules, oldRuleCnt,
				logfields.Identity, slices.Collect(truncate(regen.Members(), 100)))

		}

		idsToRegen.Merge(*regen)

		// Report that the policy has been inserted in to the repository.
		if upd.DoneChan != nil {
			upd.DoneChan <- endRevision
		}

		// Send a policy update notification
		if i.monitorAgent != nil {
			var msg monitorapi.AgentNotifyMessage
			if len(upd.Rules) > 0 {
				lbls := make([]string, 0, len(upd.Rules))
				for _, rule := range upd.Rules {
					lbls = append(lbls, rule.Labels.GetModel()...)
				}
				msg = monitorapi.PolicyUpdateMessage(len(upd.Rules), lbls, endRevision)
			} else {
				var lbls []string
				if upd.Resource != "" {
					// We are deleting by resource, not by label. So, synthesize a placeholder
					// "label" for the notification to indicate which resource was the key
					// for deletion.
					lbls = []string{
						"cilium.io/resource=" + string(upd.Resource),
					}
				} else {
					lbls = append(lbls, upd.ReplaceWithLabels.GetModel()...)
				}
				msg = monitorapi.PolicyDeleteMessage(oldRuleCnt, lbls, endRevision)
			}

			err := i.monitorAgent.SendEvent(monitorapi.MessageTypeAgent, msg)
			if err != nil {
				i.log.Error("Failed to send policy update as monitor notification", logfields.Error, err)
			}
		}
	}

	// All policy updates have been applied; regenerate all affected endpoints.
	// Unaffected endpoints can merely have their policy revision set.
	i.log.Info("Policy repository updates complete, triggering endpoint updates",
		logfields.PolicyRevision, endRevision)
	if i.epm != nil {
		i.epm.UpdatePolicy(idsToRegen, startRevision, endRevision)
	}

	// Now that the update has rolled out, record ingestion time.
	for _, upd := range updates {
		if upd.ProcessingStartTime.IsZero() {
			continue
		}
		metrics.PolicyImplementationDelay.WithLabelValues(string(upd.Source)).Observe(time.Since(upd.ProcessingStartTime).Seconds())
	}

	// Remove stale prefix metadata from the ipcache.
	i.prunePrefixes(oldPrefixes)
	return nil
}

// truncate takes an iterator and passes through at most maxLen values.
func truncate[T any](xs iter.Seq[T], maxLen int) iter.Seq[T] {
	pos := 0
	if maxLen == 0 {
		return func(func(T) bool) {}
	}
	return func(yield func(T) bool) {
		for x := range xs {
			if !yield(x) {
				return
			}
			pos++
			if pos == maxLen {
				return
			}
		}
	}
}
