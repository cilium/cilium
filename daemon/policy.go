// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfIPCache "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/safetime"
	"github.com/cilium/cilium/pkg/uuid"

	"github.com/go-openapi/runtime/middleware"
	"github.com/op/go-logging"
)

func (d *Daemon) policyUpdateTrigger(reasons []string) {
	log.Debugf("Regenerating all endpoints")
	reason := strings.Join(reasons, ", ")

	regenerationMetadata := &endpoint.ExternalRegenerationMetadata{Reason: reason}
	endpointmanager.RegenerateAllEndpoints(d, regenerationMetadata)
}

// TriggerPolicyUpdates triggers policy updates for every daemon's endpoint.
// This may be called in a variety of situations: after policy changes, changes
// in agent configuration, changes in endpoint labels, and change of security
// identities.
func (d *Daemon) TriggerPolicyUpdates(force bool, reason string) {
	if force {
		log.Debugf("Artifically increasing policy revision to enforce policy recalculation")
		d.policy.BumpRevision()
	}

	d.policyTrigger.TriggerWithReason(reason)
}

// UpdateIdentities informs the policy package of all identity changes
// and also triggers policy updates.
func (d *Daemon) UpdateIdentities(added, deleted cache.IdentityCache) {
	policy.UpdateIdentities(added, deleted)
	d.TriggerPolicyUpdates(true, "one or more identities created or deleted")
}

type getPolicyResolve struct {
	daemon *Daemon
}

func NewGetPolicyResolveHandler(d *Daemon) GetPolicyResolveHandler {
	return &getPolicyResolve{daemon: d}
}

func (h *getPolicyResolve) Handle(params GetPolicyResolveParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /policy/resolve request")

	d := h.daemon

	var policyEnforcementMsg string
	isPolicyEnforcementEnabled := true

	d.policy.Mutex.RLock()

	// If policy enforcement isn't enabled, then traffic is allowed.
	if policy.GetPolicyEnabled() == option.NeverEnforce {
		policyEnforcementMsg = "Policy enforcement is disabled for the daemon."
		isPolicyEnforcementEnabled = false
	} else if policy.GetPolicyEnabled() == option.DefaultEnforcement {
		// If there are no rules matching the set of from / to labels provided in
		// the API request, that means that policy enforcement is not enabled
		// for the endpoints corresponding to said sets of labels; thus, we allow
		// traffic between these sets of labels, and do not enforce policy between them.
		fromIngress, fromEgress := d.policy.GetRulesMatching(labels.NewSelectLabelArrayFromModel(params.TraceSelector.From.Labels))
		toIngress, toEgress := d.policy.GetRulesMatching(labels.NewSelectLabelArrayFromModel(params.TraceSelector.To.Labels))
		if !fromIngress && !fromEgress && !toIngress && !toEgress {
			policyEnforcementMsg = "Policy enforcement is disabled because " +
				"no rules in the policy repository match any endpoint selector " +
				"from the provided destination sets of labels."
			isPolicyEnforcementEnabled = false
		}
	}

	d.policy.Mutex.RUnlock()

	// Return allowed verdict if policy enforcement isn't enabled between the two sets of labels.
	if !isPolicyEnforcementEnabled {
		buffer := new(bytes.Buffer)
		ctx := params.TraceSelector
		searchCtx := policy.SearchContext{
			From:    labels.NewSelectLabelArrayFromModel(ctx.From.Labels),
			Trace:   policy.TRACE_ENABLED,
			To:      labels.NewSelectLabelArrayFromModel(ctx.To.Labels),
			DPorts:  ctx.To.Dports,
			Logging: logging.NewLogBackend(buffer, "", 0),
		}
		if ctx.Verbose {
			searchCtx.Trace = policy.TRACE_VERBOSE
		}
		verdict := policyAPI.Allowed.String()
		searchCtx.PolicyTrace("Label verdict: %s\n", verdict)
		msg := fmt.Sprintf("%s\n  %s\n%s", searchCtx.String(), policyEnforcementMsg, buffer.String())
		return NewGetPolicyResolveOK().WithPayload(&models.PolicyTraceResult{
			Log:     msg,
			Verdict: verdict,
		})
	}

	// If we hit the following code, policy enforcement is enabled for at least
	// one of the endpoints corresponding to the provided sets of labels, or for
	// the daemon.
	ingressBuffer := new(bytes.Buffer)

	ctx := params.TraceSelector
	ingressSearchCtx := policy.SearchContext{
		Trace:   policy.TRACE_ENABLED,
		Logging: logging.NewLogBackend(ingressBuffer, "", 0),
		From:    labels.NewSelectLabelArrayFromModel(ctx.From.Labels),
		To:      labels.NewSelectLabelArrayFromModel(ctx.To.Labels),
		DPorts:  ctx.To.Dports,
	}
	if ctx.Verbose {
		ingressSearchCtx.Trace = policy.TRACE_VERBOSE
	}

	// TODO: GH-3394 (add egress trace to API for policy trace).
	egressBuffer := new(bytes.Buffer)
	egressSearchCtx := ingressSearchCtx
	egressSearchCtx.Logging = logging.NewLogBackend(egressBuffer, "", 0)

	d.policy.Mutex.RLock()

	ingressVerdict := d.policy.AllowsIngressRLocked(&ingressSearchCtx)

	d.policy.Mutex.RUnlock()

	result := models.PolicyTraceResult{
		Verdict: ingressVerdict.String(),
		Log:     ingressBuffer.String(),
	}

	return NewGetPolicyResolveOK().WithPayload(&result)
}

// AddOptions are options which can be passed to PolicyAdd
type AddOptions struct {
	// Replace if true indicates that existing rules with identical labels should be replaced
	Replace bool
	// ReplaceWithLabels if present indicates that existing rules with the
	// given LabelArray should be deleted.
	ReplaceWithLabels labels.LabelArray
	// Generated should be set as true to signalize a the policy being inserted
	// was generated by cilium-agent, e.g. dns poller.
	Generated bool

	// The source of this policy, one of api, fqdn or k8s
	Source string
}

// PolicyAddEvent is a wrapper around the parameters for policyAdd.
type PolicyAddEvent struct {
	rules policyAPI.Rules
	opts  *AddOptions
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
func (d *Daemon) PolicyAdd(rules policyAPI.Rules, opts *AddOptions) (newRev uint64, err error) {
	p := &PolicyAddEvent{
		rules: rules,
		opts:  opts,
		d:     d,
	}
	polAddEvent := eventqueue.NewEvent(p)
	resChan := d.policy.RepositoryChangeQueue.Enqueue(polAddEvent)

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
func (d *Daemon) policyAdd(sourceRules policyAPI.Rules, opts *AddOptions, resChan chan interface{}) {
	policyAddStartTime := time.Now()
	logger := log.WithField("policyAddRequest", uuid.NewUUID().String())

	if opts != nil && opts.Generated {
		logger.WithField(logfields.CiliumNetworkPolicy, sourceRules.String()).Debug("Policy Add Request")
	} else {
		logger.WithField(logfields.CiliumNetworkPolicy, sourceRules.String()).Info("Policy Add Request")
	}

	// These must be marked before actually adding them to the repository since
	// a copy may be made and we won't be able to add the ToFQDN tracking
	// labels.
	// CAUTION, there is a small race between this PrepareFQDNRules invocation and
	// taking the policy lock. As long as policyAdd is fed by a single-threaded
	// queue this should never be an issue.
	rules := d.dnsRuleGen.PrepareFQDNRules(sourceRules)
	if len(rules) == 0 && len(sourceRules) > 0 {
		// All rules being added have ToFQDNs UUIDs that have been removed and
		// will not be re-inserted to avoid a race.
		err := errors.New("PrepareFQDNRules delete all sourceRules due invalid UUIDs")
		resChan <- &PolicyAddResult{
			newRev: 0,
			err:    api.Error(PutPolicyFailureCode, err),
		}
	}

	prefixes := policy.GetCIDRPrefixes(rules)
	logger.WithField("prefixes", prefixes).Debug("Policy imported via API, found CIDR prefixes...")

	newPrefixLengths, err := d.prefixLengths.Add(prefixes)
	if err != nil {
		metrics.PolicyImportErrors.Inc()
		logger.WithError(err).WithField("prefixes", prefixes).Warn(
			"Failed to reference-count prefix lengths in CIDR policy")
		resChan <- &PolicyAddResult{
			newRev: 0,
			err:    api.Error(PutPolicyFailureCode, err),
		}
		return
	}
	if newPrefixLengths && !bpfIPCache.BackedByLPM() {
		// Only recompile if configuration has changed.
		logger.Debug("CIDR policy has changed; recompiling base programs")
		if err := d.compileBase(); err != nil {
			_ = d.prefixLengths.Delete(prefixes)
			metrics.PolicyImportErrors.Inc()
			err2 := fmt.Errorf("Unable to recompile base programs: %s", err)
			logger.WithError(err2).WithField("prefixes", prefixes).Warn(
				"Failed to recompile base programs due to prefix length count change")
			resChan <- &PolicyAddResult{
				newRev: 0,
				err:    api.Error(PutPolicyFailureCode, err),
			}
			return
		}
	}

	if _, err := ipcache.AllocateCIDRs(bpfIPCache.IPCache, prefixes); err != nil {
		_ = d.prefixLengths.Delete(prefixes)
		metrics.PolicyImportErrors.Inc()
		logger.WithError(err).WithField("prefixes", prefixes).Warn(
			"Failed to allocate identities for CIDRs during policy add")
		resChan <- &PolicyAddResult{
			newRev: 0,
			err:    err,
		}
		return
	}

	// No errors past this point!

	d.policy.Mutex.Lock()

	// removedPrefixes tracks prefixes that we replace in the rules. It is used
	// after we release the policy repository lock.
	var removedPrefixes []*net.IPNet

	// policySelectionWG is used to signal when the updating of all of the
	// caches of endpoints in the rules which were added / updated have been
	// updated.
	var policySelectionWG sync.WaitGroup

	// Get all endpoints at the time rules were added / updated so we can figure
	// out which endpoints to regenerate / bump policy revision.
	allEndpoints := endpointmanager.GetEndpoints()

	// Start with all endpoints to be in set for which we need to bump their
	// revision.
	endpointsToBumpRevision := policy.NewEndpointSet(len(allEndpoints))

	// Need to explicitly convert endpoints to policy.Endpoint.
	// See: https://github.com/golang/go/wiki/InterfaceSlice
	for i := range allEndpoints {
		endpointsToBumpRevision.Insert(allEndpoints[i])
	}

	endpointsToRegen := policy.NewIDSet()

	if opts != nil {
		if opts.Replace {
			for _, r := range rules {
				oldRules := d.policy.SearchRLocked(r.Labels)
				removedPrefixes = append(removedPrefixes, policy.GetCIDRPrefixes(oldRules)...)
				if len(oldRules) > 0 {
					d.dnsRuleGen.StopManageDNSName(oldRules)
					deletedRules, _, _ := d.policy.DeleteByLabelsLocked(r.Labels)
					deletedRules.UpdateRulesEndpointsCaches(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)

				}
			}
		}
		if len(opts.ReplaceWithLabels) > 0 {
			oldRules := d.policy.SearchRLocked(opts.ReplaceWithLabels)
			removedPrefixes = append(removedPrefixes, policy.GetCIDRPrefixes(oldRules)...)
			if len(oldRules) > 0 {
				d.dnsRuleGen.StopManageDNSName(oldRules)
				deletedRules, _, _ := d.policy.DeleteByLabelsLocked(opts.ReplaceWithLabels)
				deletedRules.UpdateRulesEndpointsCaches(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)
			}
		}
	}

	addedRules, newRev := d.policy.AddListLocked(rules)

	// The information needed by the caller is available at this point, signal
	// accordingly.
	resChan <- &PolicyAddResult{
		newRev: newRev,
		err:    nil,
	}

	// The rules are added, we can begin ToFQDN DNS polling for them
	// Note: api.FQDNSelector.sanitize checks that the matchName entries are
	// valid. This error should never happen (of course).
	if err := d.dnsRuleGen.StartManageDNSName(rules); err != nil {
		log.WithError(err).Warn("Error trying to manage rules during PolicyAdd")
	}

	addedRules.UpdateRulesEndpointsCaches(endpointsToBumpRevision, endpointsToRegen, &policySelectionWG)

	d.policy.Mutex.Unlock()

	// Begin tracking the time taken to deploy newRev to the datapath. The start
	// time is from before the locking above, and thus includes all waits and
	// processing in this function.
	source := ""
	if opts != nil {
		source = opts.Source
	}
	endpointmanager.CallbackForEndpointsAtPolicyRev(context.Background(), newRev, func(now time.Time) {
		duration, _ := safetime.TimeSinceSafe(policyAddStartTime, logger)
		metrics.PolicyImplementationDelay.WithLabelValues(source).Observe(duration.Seconds())
	})

	// remove prefixes of replaced rules above. This potentially blocks on the
	// kvstore and should happen without holding the policy lock. Refcounts have
	// been incremented above, so any decrements here will be no-ops for CIDRs
	// that are re-added, and will trigger deletions for those that are no longer
	// used.
	if len(removedPrefixes) > 0 {
		logger.WithField("prefixes", removedPrefixes).Debug("Decrementing replaced CIDR refcounts when adding rules")
		ipcache.ReleaseCIDRs(removedPrefixes)
		d.prefixLengths.Delete(removedPrefixes)
	}

	logger.WithField(logfields.PolicyRevision, newRev).Info("Policy imported via API, recalculating...")

	labels := make([]string, 0, len(rules))
	for _, r := range rules {
		labels = append(labels, r.Labels.GetModel()...)
	}
	repr, err := monitorAPI.PolicyUpdateRepr(len(rules), labels, newRev)
	if err != nil {
		logger.WithField(logfields.PolicyRevision, newRev).Warn("Failed to represent policy update as monitor notification")
	} else {
		d.SendNotification(monitorAPI.AgentNotifyPolicyUpdated, repr)
	}

	if option.Config.SelectiveRegeneration {
		// Only regenerate endpoints which are needed to be regenerated as a
		// result of the rule update. The rules which were imported most likely
		// do not select all endpoints in the policy repository (and may not
		// select any at all). The "reacting" to rule updates enqueues events
		// for all endpoints. Once all endpoints have events queued up, this
		// function will return.

		r := &PolicyReactionEvent{
			d:                 d,
			wg:                &policySelectionWG,
			epsToBumpRevision: endpointsToBumpRevision,
			endpointsToRegen:  endpointsToRegen,
			newRev:            newRev,
		}

		ev := eventqueue.NewEvent(r)
		// This event may block if the RuleReactionQueue is full. We don't care
		// about when it finishes, just that the work it does is done in a serial
		// order.
		d.policy.RuleReactionQueue.Enqueue(ev)
	} else {
		// Regenerate all endpoints unconditionally.
		d.TriggerPolicyUpdates(false, "policy rules added")
	}

	return
}

// PolicyReactionEvent is an event which needs to be serialized after changes
// to a policy repository for a daemon. This currently consists of endpoint
// regenerations / policy revision incrementing for a given endpoint.
type PolicyReactionEvent struct {
	d                 *Daemon
	wg                *sync.WaitGroup
	epsToBumpRevision *policy.EndpointSet
	endpointsToRegen  *policy.IDSet
	newRev            uint64
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (r *PolicyReactionEvent) Handle(res chan interface{}) {
	r.d.ReactToRuleUpdates(r.wg, r.epsToBumpRevision, r.endpointsToRegen, r.newRev)
}

// ReactToRuleUpdates waits until wg is complete to do the following
// * regenerate all endpoints in epsToRegen
// * bump the policy revision of all endpoints not in epsToRegen, but which are
//   in allEps, to revision rev.
func (d *Daemon) ReactToRuleUpdates(wg *sync.WaitGroup, epsToBumpRevision *policy.EndpointSet, epsToRegen *policy.IDSet, rev uint64) {
	// Wait until we have calculated which endpoints need to be selected
	// across multiple goroutines.
	wg.Wait()

	var enqueueWaitGroup sync.WaitGroup

	// Bump revision of endpoints which don't need to be regenerated.
	epsToBumpRevision.ForEach(&enqueueWaitGroup, func(epp policy.Endpoint) {
		if epp == nil {
			return
		}
		epp.PolicyRevisionBumpEvent(rev)
	})

	epsToRegen.Mutex.RLock()
	// Regenerate all other endpoints.
	endpointmanager.RegenerateEndpointSetSignalWhenEnqueued(d, &endpoint.ExternalRegenerationMetadata{Reason: "policy rules added"}, epsToRegen.IDs, &enqueueWaitGroup)
	epsToRegen.Mutex.RUnlock()

	enqueueWaitGroup.Wait()
}

// PolicyDeleteEvent is a wrapper around deletion of policy rules with a given
// set of labels from the policy repository in the daemon.
type PolicyDeleteEvent struct {
	labels labels.LabelArray
	d      *Daemon
}

// Handle implements pkg/eventqueue/EventHandler interface.
func (p *PolicyDeleteEvent) Handle(res chan interface{}) {
	p.d.policyDelete(p.labels, res)
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
func (d *Daemon) PolicyDelete(labels labels.LabelArray) (newRev uint64, err error) {

	p := &PolicyDeleteEvent{
		labels: labels,
		d:      d,
	}
	policyDeleteEvent := eventqueue.NewEvent(p)
	resChan := d.policy.RepositoryChangeQueue.Enqueue(policyDeleteEvent)

	res, ok := <-resChan
	if ok {
		ress := res.(*PolicyDeleteResult)
		return ress.newRev, ress.err
	}
	return 0, fmt.Errorf("policy deletion event cancelled")
}

func (d *Daemon) policyDelete(labels labels.LabelArray, res chan interface{}) {
	log.WithField(logfields.IdentityLabels, logfields.Repr(labels)).Debug("Policy Delete Request")

	d.policy.Mutex.Lock()

	// First, find rules by the label. We'll use this set of rules to
	// determine which CIDR identities that we need to release.
	rules := d.policy.SearchRLocked(labels)

	// Return an error if a label filter was provided and there are no
	// rules matching it. A deletion request for all policy entries should
	// not fail if no policies are loaded.
	if len(rules) == 0 && len(labels) != 0 {
		rev := d.policy.GetRevision()
		d.policy.Mutex.Unlock()

		err := api.New(DeletePolicyNotFoundCode, "policy not found")

		res <- &PolicyDeleteResult{
			newRev: rev,
			err:    err,
		}
		return
	}

	// policySelectionWG is used to signal when the updating of all of the
	// caches of allEndpoints in the rules which were added / updated have been
	// updated.
	var policySelectionWG sync.WaitGroup

	// Get all endpoints at the time rules were added / updated so we can figure
	// out which endpoints to regenerate / bump policy revision.
	allEndpoints := endpointmanager.GetEndpoints()
	epsToBumpRevision := policy.NewEndpointSet(len(allEndpoints))

	// Initially keep all endpoints in set of endpoints which need to have
	// revision bumped.
	for i := range allEndpoints {
		epsToBumpRevision.Insert(allEndpoints[i])
	}

	endpointsToRegen := policy.NewIDSet()

	deletedRules, rev, deleted := d.policy.DeleteByLabelsLocked(labels)
	deletedRules.UpdateRulesEndpointsCaches(epsToBumpRevision, endpointsToRegen, &policySelectionWG)

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
	prefixes := policy.GetCIDRPrefixes(rules)
	log.WithField("prefixes", prefixes).Debug("Policy deleted via API, found prefixes...")
	ipcache.ReleaseCIDRs(prefixes)

	prefixesChanged := d.prefixLengths.Delete(prefixes)
	if !bpfIPCache.BackedByLPM() && prefixesChanged {
		// Only recompile if configuration has changed.
		log.Debug("CIDR policy has changed; recompiling base programs")
		if err := d.compileBase(); err != nil {
			log.WithError(err).Error("Unable to recompile base programs")
		}
	}

	// Stop polling for ToFQDN DNS names for these rules
	d.dnsRuleGen.StopManageDNSName(rules)

	if option.Config.SelectiveRegeneration {
		r := &PolicyReactionEvent{
			d:                 d,
			wg:                &policySelectionWG,
			epsToBumpRevision: epsToBumpRevision,
			endpointsToRegen:  endpointsToRegen,
			newRev:            rev,
		}

		ev := eventqueue.NewEvent(r)
		// This event may block if the RuleReactionQueue is full. We don't care
		// about when it finishes, just that the work it does is done in a serial
		// order.
		d.policy.RuleReactionQueue.Enqueue(ev)
	} else {
		d.TriggerPolicyUpdates(true, "policy rules deleted")
	}

	repr, err := monitorAPI.PolicyDeleteRepr(deleted, labels.GetModel(), rev)
	if err != nil {
		log.WithField(logfields.PolicyRevision, rev).Warn("Failed to represent policy update as monitor notification")
	} else {
		d.SendNotification(monitorAPI.AgentNotifyPolicyDeleted, repr)
	}

	return
}

type deletePolicy struct {
	daemon *Daemon
}

func newDeletePolicyHandler(d *Daemon) DeletePolicyHandler {
	return &deletePolicy{daemon: d}
}

func (h *deletePolicy) Handle(params DeletePolicyParams) middleware.Responder {
	d := h.daemon
	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	rev, err := d.PolicyDelete(lbls)
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

type putPolicy struct {
	daemon *Daemon
}

func newPutPolicyHandler(d *Daemon) PutPolicyHandler {
	return &putPolicy{daemon: d}
}

func (h *putPolicy) Handle(params PutPolicyParams) middleware.Responder {
	d := h.daemon

	var rules policyAPI.Rules
	if err := json.Unmarshal([]byte(params.Policy), &rules); err != nil {
		return NewPutPolicyInvalidPolicy()
	}

	for _, r := range rules {
		if err := r.Sanitize(); err != nil {
			return api.Error(PutPolicyFailureCode, err)
		}
	}

	rev, err := d.PolicyAdd(rules, &AddOptions{Source: metrics.LabelEventSourceAPI})
	if err != nil {
		return api.Error(PutPolicyFailureCode, err)
	}

	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(rules),
	}
	return NewPutPolicyOK().WithPayload(policy)
}

type getPolicy struct {
	daemon *Daemon
}

func newGetPolicyHandler(d *Daemon) GetPolicyHandler {
	return &getPolicy{daemon: d}
}

func (h *getPolicy) Handle(params GetPolicyParams) middleware.Responder {
	d := h.daemon
	d.policy.Mutex.RLock()
	defer d.policy.Mutex.RUnlock()

	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	ruleList := d.policy.SearchRLocked(lbls)

	// Error if labels have been specified but no entries found, otherwise,
	// return empty list
	if len(ruleList) == 0 && len(lbls) != 0 {
		return NewGetPolicyNotFound()
	}

	policy := &models.Policy{
		Revision: int64(d.policy.GetRevision()),
		Policy:   policy.JSONMarshalRules(ruleList),
	}
	return NewGetPolicyOK().WithPayload(policy)
}
