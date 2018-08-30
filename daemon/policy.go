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
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfIPCache "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"

	"github.com/go-openapi/runtime/middleware"
	"github.com/op/go-logging"
)

// TriggerPolicyUpdates triggers policy updates for every daemon's endpoint.
// This may be called in a variety of situations: after policy changes, changes
// in agent configuration, changes in endpoint labels, and change of security
// identities.
// Returns a waiting group which signals when all endpoints are regenerated.
func (d *Daemon) TriggerPolicyUpdates(force bool, reason string) *sync.WaitGroup {
	if force {
		d.policy.BumpRevision() // force policy recalculation
		log.Debugf("Forced policy recalculation triggered")
	} else {
		log.Debugf("Full policy recalculation triggered")
	}
	regenContext := endpoint.NewRegenerationContext(reason)
	return endpointmanager.RegenerateAllEndpoints(d, regenContext)
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
}

// PolicyAdd adds a slice of rules to the policy repository owned by the
// daemon.  Policy enforcement is automatically enabled if currently disabled if
// k8s is not enabled. Otherwise, if k8s is enabled, policy is enabled on the
// pods which are selected. Eventual changes in policy rules are propagated to
// all locally managed endpoints.
func (d *Daemon) PolicyAdd(rules policyAPI.Rules, opts *AddOptions) (uint64, error) {
	log.WithField(logfields.CiliumNetworkPolicy, logfields.Repr(rules)).Debug("Policy Add Request")

	// These must be marked before actually adding them to the repository since a
	// copy may be made and we won't be able to add the ToFQDN tracking labels
	d.dnsPoller.MarkToFQDNRules(rules)

	prefixes := policy.GetCIDRPrefixes(rules)
	log.WithField("prefixes", prefixes).Debug("Policy imported via API, found CIDR prefixes...")

	newPrefixLengths, err := d.prefixLengths.Add(prefixes)
	if err != nil {
		metrics.PolicyImportErrors.Inc()
		log.WithError(err).WithField("prefixes", prefixes).Warn(
			"Failed to reference-count prefix lengths in CIDR policy")
		return 0, api.Error(PutPolicyFailureCode, err)
	}
	if newPrefixLengths && !bpfIPCache.BackedByLPM() {
		// Only recompile if configuration has changed.
		log.Debug("CIDR policy has changed; recompiling base programs")
		if err := d.compileBase(); err != nil {
			_ = d.prefixLengths.Delete(prefixes)
			metrics.PolicyImportErrors.Inc()
			err2 := fmt.Errorf("Unable to recompile base programs: %s", err)
			log.WithError(err2).WithField("prefixes", prefixes).Warn(
				"Failed to recompile base programs due to prefix length count change")
			return 0, api.Error(PutPolicyFailureCode, err)
		}
	}

	if err := ipcache.AllocateCIDRs(bpfIPCache.IPCache, prefixes); err != nil {
		_ = d.prefixLengths.Delete(prefixes)
		metrics.PolicyImportErrors.Inc()
		log.WithError(err).WithField("prefixes", prefixes).Warn(
			"Failed to allocate identities for CIDRs during policy add")
		return d.policy.GetRevision(), err
	}

	d.policy.Mutex.Lock()
	if opts != nil && opts.Replace {
		for _, r := range rules {
			tmp := d.policy.SearchRLocked(r.Labels)
			if len(tmp) > 0 {
				d.policy.DeleteByLabelsLocked(r.Labels)
			}
		}
	}
	rev := d.policy.AddListLocked(rules)
	d.policy.Mutex.Unlock()

	// The rules are added, we can begin ToFQDN DNS polling for them
	d.dnsPoller.StartPollForDNSName(rules)

	log.WithField(logfields.PolicyRevision, rev).Info("Policy imported via API, recalculating...")

	d.TriggerPolicyUpdates(false, "policy rules added")

	repr, err := monitor.PolicyUpdateRepr(rules, rev)
	if err != nil {
		log.WithField(logfields.PolicyRevision, rev).Warn("Failed to represent policy update as monitor notification")
	} else {
		d.SendNotification(monitor.AgentNotifyPolicyUpdated, repr)
	}

	return rev, nil
}

// PolicyDelete deletes the policy set in the given path from the policy tree.
// If cover256Sum is set it finds the rule with the respective coverage that
// rule from the node. If the path's node becomes ruleless it is removed from
// the tree.
// Returns the revision number and an error in case it was not possible to
// delete the policy.
func (d *Daemon) PolicyDelete(labels labels.LabelArray) (uint64, error) {
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
		return rev, api.New(DeletePolicyNotFoundCode, "policy not found")
	}
	rev, deleted := d.policy.DeleteByLabelsLocked(labels)
	d.policy.Mutex.Unlock()

	// Now that the policies are deleted, we can also attempt to remove
	// all CIDR identities referenced by the deleted rules.
	//
	// We don't treat failures to clean up identities as API failures,
	// because the policy can still successfully be updated. We're just
	// not appropriately performing garbage collection.
	prefixes := policy.GetCIDRPrefixes(rules)
	log.WithField("prefixes", prefixes).Debug("Policy deleted via API, found prefixes...")
	if err := ipcache.ReleaseCIDRs(prefixes); err != nil {
		log.WithError(err).WithField("prefixes", prefixes).Warn(
			"Failed to release CIDRs during policy delete")
	}

	prefixesChanged := d.prefixLengths.Delete(prefixes)
	if !bpfIPCache.BackedByLPM() && prefixesChanged {
		// Only recompile if configuration has changed.
		log.Debug("CIDR policy has changed; recompiling base programs")
		if err := d.compileBase(); err != nil {
			log.WithError(err).Error("Unable to recompile base programs")
		}
	}

	// Stop polling for ToFQDN DNS names for these rules
	d.dnsPoller.StopPollForDNSName(rules)

	d.TriggerPolicyUpdates(false, "policy rules deleted")

	repr, err := monitor.PolicyDeleteRepr(deleted, labels.GetModel(), rev)
	if err != nil {
		log.WithField(logfields.PolicyRevision, rev).Warn("Failed to represent policy update as monitor notification")
	} else {
		d.SendNotification(monitor.AgentNotifyPolicyDeleted, repr)
	}

	return rev, nil
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
	if err := json.Unmarshal([]byte(*params.Policy), &rules); err != nil {
		return NewPutPolicyInvalidPolicy()
	}

	for _, r := range rules {
		if err := r.Sanitize(); err != nil {
			return api.Error(PutPolicyFailureCode, err)
		}
	}

	rev, err := d.PolicyAdd(rules, nil)
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
