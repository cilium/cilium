// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
	"github.com/go-openapi/runtime/middleware"
	"github.com/google/uuid"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/safetime"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type policyParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	EndpointManager endpointmanager.EndpointManager
	CertManager     certificatemanager.CertificateManager
	SecretManager   certificatemanager.SecretManager
	IdentityManager *identitymanager.IdentityManager
	CacheStatus     synced.CacheStatus
	ClusterInfo     cmtypes.ClusterInfo
}

type policyOut struct {
	cell.Out

	IdentityAllocator      CachingIdentityAllocator
	CacheIdentityAllocator cache.IdentityAllocator
	RemoteIdentityWatcher  clustermesh.RemoteIdentityWatcher
	IdentityObservable     stream.Observable[cache.IdentityChange]

	Repository *policy.Repository
	Updater    *policy.Updater
	IPCache    *ipcache.IPCache
}

// newPolicyTrifecta instantiates CachingIdentityAllocator, Repository and IPCache,
// which in turn creates the SelectorCache and other policy components.
//
// The three have a complicated dependency on each other and therefore require
// special care.
func newPolicyTrifecta(params policyParams) (policyOut, error) {
	ctx, cancel := context.WithCancel(context.Background())
	if option.Config.EnableWellKnownIdentities {
		// Must be done before calling policy.NewPolicyRepository() below.
		num := identity.InitWellKnownIdentities(option.Config, params.ClusterInfo)
		metrics.Identity.WithLabelValues(identity.WellKnownIdentityType).Add(float64(num))
		identity.WellKnown.ForEach(func(i *identity.Identity) {
			for labelSource := range i.Labels.CollectSources() {
				metrics.IdentityLabelSources.WithLabelValues(labelSource).Inc()
			}
		})
	}

	// policy repository: maintains list of active Rules and their subject
	// security identities. Also constructs the SelectorCache, a precomputed
	// cache of label selector -> identities for policy peers.
	repo := policy.NewStoppedPolicyRepository(
		identity.ListReservedIdentities(), // Load SelectorCache with reserved identities
		params.CertManager,
		params.SecretManager,
		params.IdentityManager,
	)
	repo.SetEnvoyRulesFunc(envoy.GetEnvoyHTTPRules)

	// policyUpdater: forces policy recalculation on all endpoints.
	// Called for various events, such as named port changes
	// or certain identity updates.
	policyUpdater := policy.NewUpdater(repo, params.EndpointManager)

	// iao: updates SelectorCache and regenerates endpoints when
	// identity allocation / deallocation has occurred.
	iao := &identityAllocatorOwner{
		policy:        repo,
		policyUpdater: policyUpdater,
	}

	// Allocator: allocates local and cluster-wide security identities.
	idAlloc := cache.NewCachingIdentityAllocator(iao)
	idAlloc.EnableCheckpointing()

	// IPCache: aggregates node-local prefix labels and allocates
	// local identities. Generates incremental updates, pushes
	// to endpoints.
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           ctx,
		IdentityAllocator: idAlloc,
		PolicyHandler:     iao.policy.GetSelectorCache(),
		DatapathHandler:   params.EndpointManager,
		CacheStatus:       params.CacheStatus,
	})

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			iao.policy.Start()
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			// Preserve the order of shutdown but still propagate the error
			// to hive.
			err := ipc.Shutdown()
			policyUpdater.Shutdown()
			idAlloc.Close()

			return err
		},
	})

	return policyOut{
		IdentityAllocator:      idAlloc,
		CacheIdentityAllocator: idAlloc,
		RemoteIdentityWatcher:  idAlloc,
		IdentityObservable:     idAlloc,
		Repository:             iao.policy,
		Updater:                policyUpdater,
		IPCache:                ipc,
	}, nil
}

// identityAllocatorOwner is used to break the circular dependency between
// CachingIdentityAllocator and policy.Repository.
type identityAllocatorOwner struct {
	policy        *policy.Repository
	policyUpdater *policy.Updater
}

// UpdateIdentities informs the policy package of all identity changes
// and also triggers policy updates.
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (iao *identityAllocatorOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
	wg := &sync.WaitGroup{}
	iao.policy.GetSelectorCache().UpdateIdentities(added, deleted, wg)
	// Wait for update propagation to endpoints before triggering policy updates
	wg.Wait()
	iao.policyUpdater.TriggerPolicyUpdates(false, "one or more identities created or deleted")
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (iao *identityAllocatorOwner) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetIPv4()
	case option.Config.EnableIPv6:
		ip = node.GetIPv6()
	}

	if ip == nil {
		log.Fatal("Node IP not available yet")
	}

	return ip.String()
}

// PolicyAddEvent is a wrapper around the parameters for policyAdd.
type PolicyAddEvent struct {
	rules policyAPI.Rules
	opts  *policy.AddOptions
	d     *Daemon
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (p *PolicyAddEvent) Handle(res chan interface{}) {
	p.d.policyAdd(p.rules, p.opts, res)
}

// PolicyAddResult is a wrapper around the values returned by policyAdd. It
// contains the new revision of a policy repository after adding a list of rules
// to it, and any error associated with adding rules to said repository.
type PolicyAddResult struct {
	newRev uint64
	err    error
}

// PolicyAdd adds a slice of rules to the policy repository owned by the
// daemon. Eventual changes in policy rules are propagated to all locally
// managed endpoints. Returns the policy revision number of the repository after
// adding the rules into the repository, or an error if the updated policy
// was not able to be imported.
func (d *Daemon) PolicyAdd(rules policyAPI.Rules, opts *policy.AddOptions) (newRev uint64, err error) {
	p := &PolicyAddEvent{
		rules: rules,
		opts:  opts,
		d:     d,
	}
	polAddEvent := eventqueue.NewEvent(p)
	resChan, err := d.policy.RepositoryChangeQueue.Enqueue(polAddEvent)
	if err != nil {
		return 0, fmt.Errorf("enqueue of PolicyAddEvent failed: %w", err)
	}

	res, ok := <-resChan
	if ok {
		pRes := res.(*PolicyAddResult)
		return pRes.newRev, pRes.err
	}
	return 0, fmt.Errorf("policy addition event was cancelled")
}

// policyAdd adds a slice of rules to the policy repository owned by the
// daemon. Eventual changes in policy rules are propagated to all locally
// managed endpoints. Returns the policy revision number of the repository after
// adding the rules into the repository, or an error if the updated policy
// was not able to be imported.
func (d *Daemon) policyAdd(sourceRules policyAPI.Rules, opts *policy.AddOptions, resChan chan interface{}) {
	policyAddStartTime := time.Now()
	if opts != nil && !opts.ProcessingStartTime.IsZero() {
		policyAddStartTime = opts.ProcessingStartTime
	}
	logger := log.WithField("policyAddRequest", uuid.New().String())

	if opts != nil && opts.Generated {
		logger.WithField(logfields.CiliumNetworkPolicy, sourceRules.String()).Debug("Policy Add Request")
	} else {
		logger.WithField(logfields.CiliumNetworkPolicy, sourceRules.String()).Info("Policy Add Request")
	}

	prefixes := policy.GetCIDRPrefixes(sourceRules)
	logger.WithField("prefixes", prefixes).Debug("Policy imported via API, found CIDR prefixes...")

	// No errors past this point!

	d.policy.Mutex.Lock()

	// removedPrefixes tracks prefixes that we replace in the rules. It is used
	// after we release the policy repository lock.
	var removedPrefixes []netip.Prefix

	// policySelectionWG is used to signal when the updating of all of the
	// caches of endpoints in the rules which were added / updated have been
	// updated.
	var policySelectionWG sync.WaitGroup

	// newRev is the new policy revision after rule updates
	var newRev uint64

	// Get all endpoints at the time rules were added / updated so we can figure
	// out which endpoints to regenerate / bump policy revision.
	allEndpoints := d.endpointManager.GetPolicyEndpoints()

	// Start with all endpoints to be in set for which we need to bump their
	// revision.
	endpointsToBumpRevision := policy.NewEndpointSet(allEndpoints)

	endpointsToRegen := policy.NewEndpointSet(nil)

	// Policies can be upserted one of two ways: by labels or by resource.
	// Here we replace by resource if specified.
	// This block of code is, sadly, copy-pasty because DeleteByLabels / AddList return an unexported type.
	if opts != nil && opts.ReplaceByResource && len(opts.Resource) > 0 {
		// Update the policy repository with the new rules
		addedRules, deletedRules, rev := d.policy.ReplaceByResourceLocked(sourceRules, opts.Resource)
		newRev = rev

		if len(deletedRules) > 0 {
			// Record any prefix allocations that should be deleted
			removedPrefixes = append(removedPrefixes, policy.GetCIDRPrefixes(deletedRules.AsPolicyRules())...)

			// Determine which endpoints, if any, need to be regenerated due to removing these rules
			deletedRules.FindSelectedEndpoints(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)
			d.policy.Release(deletedRules)
		}

		// The information needed by the caller is available at this point, signal
		// accordingly.
		resChan <- &PolicyAddResult{
			newRev: newRev,
			err:    nil,
		}

		// Determine which endpoints, if any, need to be regenerated due to being selected by a new rule
		addedRules.FindSelectedEndpoints(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)

	} else {
		// Replacing by labels
		// This only happens if a policy is specified via the gRPC API. It is much less efficient
		// due to needing to scan the entire repository to find matching labels.
		if opts != nil {
			if opts.Replace {
				for _, r := range sourceRules {
					oldRules := d.policy.SearchRLocked(r.Labels)
					removedPrefixes = append(removedPrefixes, policy.GetCIDRPrefixes(oldRules)...)
					if len(oldRules) > 0 {
						deletedRules, _, _ := d.policy.DeleteByLabelsLocked(r.Labels)
						deletedRules.FindSelectedEndpoints(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)
						d.policy.Release(deletedRules)
					}
				}
			}
			if len(opts.ReplaceWithLabels) > 0 {
				oldRules := d.policy.SearchRLocked(opts.ReplaceWithLabels)
				removedPrefixes = append(removedPrefixes, policy.GetCIDRPrefixes(oldRules)...)
				if len(oldRules) > 0 {
					deletedRules, _, _ := d.policy.DeleteByLabelsLocked(opts.ReplaceWithLabels)
					deletedRules.FindSelectedEndpoints(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)
					d.policy.Release(deletedRules)
				}
			}
		}

		addedRules, rev := d.policy.AddListLocked(sourceRules)
		newRev = rev

		// The information needed by the caller is available at this point, signal
		// accordingly.
		resChan <- &PolicyAddResult{
			newRev: newRev,
			err:    nil,
		}

		addedRules.FindSelectedEndpoints(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)
	}

	d.policy.Mutex.Unlock()

	// Begin tracking the time taken to deploy newRev to the datapath. The start
	// time is from before the locking above, and thus includes all waits and
	// processing in this function.
	source := ""
	if opts != nil {
		source = string(opts.Source)
	}
	d.endpointManager.CallbackForEndpointsAtPolicyRev(d.ctx, newRev, func(now time.Time) {
		duration, _ := safetime.TimeSinceSafe(policyAddStartTime, logger)
		metrics.PolicyImplementationDelay.WithLabelValues(source).Observe(duration.Seconds())
	})

	logger.WithField(logfields.PolicyRevision, newRev).Info("Policy imported via API, recalculating...")

	labels := make([]string, 0, len(sourceRules))
	for _, r := range sourceRules {
		labels = append(labels, r.Labels.GetModel()...)
	}
	err := d.SendNotification(monitorAPI.PolicyUpdateMessage(len(sourceRules), labels, newRev))
	if err != nil {
		logger.WithError(err).WithField(logfields.PolicyRevision, newRev).Warn("Failed to send policy update as monitor notification")
	}

	// Only regenerate endpoints which are needed to be regenerated as a
	// result of the rule update. The rules which were imported most likely
	// do not select all endpoints in the policy repository (and may not
	// select any at all). The "reacting" to rule updates enqueues events
	// for all endpoints. Once all endpoints have events queued up, this
	// function will return.
	//
	// Upserting CIDRs to ipcache is performed after endpoint regeneration
	// and serialized with the corresponding ipcache deletes via the
	// policy reaction queue.
	r := &PolicyReactionEvent{
		d:                 d,
		wg:                &policySelectionWG,
		epsToBumpRevision: endpointsToBumpRevision,
		endpointsToRegen:  endpointsToRegen,
		newRev:            newRev,
		upsertPrefixes:    prefixes,
		releasePrefixes:   removedPrefixes,
		source:            opts.Source,
		resource:          opts.Resource,
	}

	ev := eventqueue.NewEvent(r)
	// This event may block if the RuleReactionQueue is full. We don't care
	// about when it finishes, just that the work it does is done in a serial
	// order.
	_, err = d.policy.RuleReactionQueue.Enqueue(ev)
	if err != nil {
		log.WithError(err).WithField(logfields.PolicyRevision, newRev).Error("enqueue of RuleReactionEvent failed")
	}
}

// PolicyReactionEvent is an event which needs to be serialized after changes
// to a policy repository for a daemon. This currently consists of endpoint
// regenerations / policy revision incrementing for a given endpoint.
type PolicyReactionEvent struct {
	d                 *Daemon
	wg                *sync.WaitGroup
	epsToBumpRevision *policy.EndpointSet
	endpointsToRegen  *policy.EndpointSet
	newRev            uint64
	upsertPrefixes    []netip.Prefix
	releasePrefixes   []netip.Prefix
	source            source.Source
	resource          ipcacheTypes.ResourceID
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (r *PolicyReactionEvent) Handle(res chan interface{}) {
	// Wait until we have calculated which endpoints need to be selected
	// across multiple goroutines.
	r.wg.Wait()
	r.reactToRuleUpdates(r.epsToBumpRevision, r.endpointsToRegen, r.newRev, r.upsertPrefixes, r.releasePrefixes)
}

// reactToRuleUpdates does the following:
//   - regenerate all endpoints in epsToRegen
//   - bump the policy revision of all endpoints not in epsToRegen, but which are
//     in allEps, to revision rev.
//   - wait for the all endpoint regenerations to be _queued_.
//   - upsert or delete CIDR identities to the ipcache, as needed.
func (r *PolicyReactionEvent) reactToRuleUpdates(epsToBumpRevision, epsToRegen *policy.EndpointSet, rev uint64, upsertPrefixes, releasePrefixes []netip.Prefix) {
	var enqueueWaitGroup sync.WaitGroup

	// Asynchronously remove the CIDRs from the IPCache, potentially
	// causing release of the corresponding identities if now unused.
	// We can proceed with policy regeneration for endpoints even without
	// ensuring that the ipcache is updated because:
	// - If another policy still selects the CIDR, the corresponding
	//   identity will remain live due to the other CIDR. Policy update
	//   is a no-op for that CIDR.
	// - If the policy being deleted is the last policy referring to this
	//   CIDR, then the policy rules will be updated to remove the allow
	//   for the CIDR below. The traffic would begin to be dropped after
	//   this operation completes regardless of whether the BPF ipcache or
	//   policymap gets updated first, so the ordering is not consequential.
	if len(releasePrefixes) != 0 {
		r.d.ipcache.RemovePrefixes(releasePrefixes, r.source, r.resource)
	}

	// Bump revision of endpoints which don't need to be regenerated.
	epsToBumpRevision.ForEachGo(&enqueueWaitGroup, func(epp policy.Endpoint) {
		if epp == nil {
			return
		}
		epp.PolicyRevisionBumpEvent(rev)
	})

	// Regenerate all other endpoints.
	//
	// This recalculates the policy for the endpoints, taking into account
	// the latest changes from this event. Any references to new CIDRs
	// will be processed to determine the selectors for those CIDRs and
	// prepare the SelectorCache for the CIDR identites. However, at this
	// point the CIDR identities may not yet exist. They'll be created in
	// ipcache.UpsertPrefixes() below, which will separately update the
	// SelectorCache and plumb the datapath for the corresponding BPF
	// policymap and ipcache map entries.
	regenMetadata := &regeneration.ExternalRegenerationMetadata{
		Reason:            "policy rules added",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
	}
	epsToRegen.ForEachGo(&enqueueWaitGroup, func(ep policy.Endpoint) {
		if ep != nil {
			switch e := ep.(type) {
			case *endpoint.Endpoint:
				// Do not wait for the returned channel as we want this to be
				// ASync
				e.RegenerateIfAlive(regenMetadata)
			default:
				log.Errorf("BUG: endpoint not type of *endpoint.Endpoint, received '%s' instead", e)
			}
		}
	})

	enqueueWaitGroup.Wait()

	// Asynchronously allocate identities for new CIDRs and notify the
	// SelectorCache / Endpoints to do an incremental identity update to
	// the datapath maps (if necessary).
	if len(upsertPrefixes) != 0 {
		r.d.ipcache.UpsertPrefixes(upsertPrefixes, r.source, r.resource)
	}
}

// PolicyDeleteEvent is a wrapper around deletion of policy rules with a given
// set of labels from the policy repository in the daemon.
type PolicyDeleteEvent struct {
	labels labels.LabelArray
	opts   *policy.DeleteOptions
	d      *Daemon
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (p *PolicyDeleteEvent) Handle(res chan interface{}) {
	p.d.policyDelete(p.labels, p.opts, res)
}

// PolicyDeleteResult is a wrapper around the values returned by policyDelete.
// It contains the new revision of a policy repository after deleting a list of
// rules to it, and any error associated with adding rules to said repository.
type PolicyDeleteResult struct {
	newRev uint64
	err    error
}

// PolicyDelete deletes the policy rules with the provided set of labels from
// the policy repository of the daemon.
// Returns the revision number and an error in case it was not possible to
// delete the policy.
func (d *Daemon) PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error) {
	p := &PolicyDeleteEvent{
		labels: labels,
		opts:   opts,
		d:      d,
	}
	policyDeleteEvent := eventqueue.NewEvent(p)
	resChan, err := d.policy.RepositoryChangeQueue.Enqueue(policyDeleteEvent)
	if err != nil {
		return 0, fmt.Errorf("enqueue of PolicyDeleteEvent failed: %w", err)
	}

	res, ok := <-resChan
	if ok {
		ress := res.(*PolicyDeleteResult)
		return ress.newRev, ress.err
	}
	return 0, fmt.Errorf("policy deletion event cancelled")
}

func (d *Daemon) policyDelete(labels labels.LabelArray, opts *policy.DeleteOptions, res chan interface{}) {
	log.WithField(logfields.IdentityLabels, logfields.Repr(labels)).Debug("Policy Delete Request")

	d.policy.Mutex.Lock()

	// policySelectionWG is used to signal when the updating of all of the
	// caches of allEndpoints in the rules which were added / updated have been
	// updated.
	var policySelectionWG sync.WaitGroup

	// Get all endpoints at the time rules were added / updated so we can figure
	// out which endpoints to regenerate / bump policy revision.
	allEndpoints := d.endpointManager.GetPolicyEndpoints()
	// Initially keep all endpoints in set of endpoints which need to have
	// revision bumped.
	epsToBumpRevision := policy.NewEndpointSet(allEndpoints)

	endpointsToRegen := policy.NewEndpointSet(nil)

	var deleted int
	var rev uint64
	var prefixes []netip.Prefix

	if opts.DeleteByResource && len(opts.Resource) > 0 {
		deletedRules, newRev := d.policy.DeleteByResourceLocked(opts.Resource)
		rev = newRev
		deleted = len(deletedRules)

		deletedRules.FindSelectedEndpoints(epsToBumpRevision, endpointsToRegen, &policySelectionWG)
		d.policy.Release(deletedRules)
		prefixes = policy.GetCIDRPrefixes(deletedRules.AsPolicyRules())
	} else {

		deletedRules, newRev, _ := d.policy.DeleteByLabelsLocked(labels)
		rev = newRev
		deleted = len(deletedRules)

		// Return an error if a label filter was provided and there are no
		// rules matching it. A deletion request for all policy entries should
		// not fail if no policies are loaded.
		if len(deletedRules) == 0 && len(labels) != 0 {
			rev := d.policy.GetRevision()
			d.policy.Mutex.Unlock()

			err := api.New(DeletePolicyNotFoundCode, "policy not found")

			res <- &PolicyDeleteResult{
				newRev: rev,
				err:    err,
			}
			return
		}

		deletedRules.FindSelectedEndpoints(epsToBumpRevision, endpointsToRegen, &policySelectionWG)
		d.policy.Release(deletedRules)
		prefixes = policy.GetCIDRPrefixes(deletedRules.AsPolicyRules())
	}

	res <- &PolicyDeleteResult{
		newRev: rev,
		err:    nil,
	}

	d.policy.Mutex.Unlock()

	// Now that the policies are deleted, we can also attempt to remove
	// all CIDR identities referenced by the deleted rules.
	//
	// We don't treat failures to clean up identities as API failures,
	// because the policy can still successfully be updated. We're just
	// not appropriately performing garbage collection.
	log.WithField("prefixes", prefixes).Debug("Policy deleted via API, found prefixes...")

	// Updates to the datapath are serialized via the policy reaction queue.
	// This way there is a canonical ordering for policy updates and hence
	// the subsequent Endpoint regenerations and ipcache updates.
	r := &PolicyReactionEvent{
		d:                 d,
		wg:                &policySelectionWG,
		epsToBumpRevision: epsToBumpRevision,
		endpointsToRegen:  endpointsToRegen,
		newRev:            rev,
		releasePrefixes:   prefixes,
		source:            opts.Source,
		resource:          opts.Resource,
	}

	ev := eventqueue.NewEvent(r)
	// This event may block if the RuleReactionQueue is full. We don't care
	// about when it finishes, just that the work it does is done in a serial
	// order.
	if _, err := d.policy.RuleReactionQueue.Enqueue(ev); err != nil {
		log.WithError(err).WithField(logfields.PolicyRevision, rev).Error("enqueue of RuleReactionEvent failed")
	}
	if err := d.SendNotification(monitorAPI.PolicyDeleteMessage(deleted, labels.GetModel(), rev)); err != nil {
		log.WithError(err).WithField(logfields.PolicyRevision, rev).Warn("Failed to send policy update as monitor notification")
	}
}

func deletePolicyHandler(d *Daemon, params DeletePolicyParams) middleware.Responder {
	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	rev, err := d.PolicyDelete(lbls, &policy.DeleteOptions{Source: source.LocalAPI})
	if err != nil {
		return api.Error(DeletePolicyFailureCode, err)
	}

	ruleList := d.policy.SearchRLocked(labels.LabelArray{})
	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(ruleList),
	}
	return NewDeletePolicyOK().WithPayload(policy)
}

func putPolicyHandler(d *Daemon, params PutPolicyParams) middleware.Responder {
	var rules policyAPI.Rules
	if err := json.Unmarshal([]byte(params.Policy), &rules); err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		return NewPutPolicyInvalidPolicy()
	}

	for _, r := range rules {
		if err := r.Sanitize(); err != nil {
			metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
			return api.Error(PutPolicyFailureCode, err)
		}
	}

	replace := false
	if params.Replace != nil {
		replace = *params.Replace
	}
	replaceWithLabels := labels.ParseSelectLabelArrayFromArray(params.ReplaceWithLabels)

	rev, err := d.PolicyAdd(rules, &policy.AddOptions{
		Replace:           replace,
		ReplaceWithLabels: replaceWithLabels,
		Source:            source.LocalAPI,
	})
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		return api.Error(PutPolicyFailureCode, err)
	}
	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()

	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(rules),
	}
	return NewPutPolicyOK().WithPayload(policy)
}

func getPolicyHandler(d *Daemon, params GetPolicyParams) middleware.Responder {
	repository := d.policy
	repository.Mutex.RLock()
	defer repository.Mutex.RUnlock()

	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	ruleList := repository.SearchRLocked(lbls)

	// Error if labels have been specified but no entries found, otherwise,
	// return empty list
	if len(ruleList) == 0 && len(lbls) != 0 {
		return NewGetPolicyNotFound()
	}

	policy := &models.Policy{
		Revision: int64(repository.GetRevision()),
		Policy:   policy.JSONMarshalRules(ruleList),
	}
	return NewGetPolicyOK().WithPayload(policy)
}

func getPolicySelectorsHandler(d *Daemon, params GetPolicySelectorsParams) middleware.Responder {
	return NewGetPolicySelectorsOK().WithPayload(d.policy.GetSelectorCache().GetModel())
}
