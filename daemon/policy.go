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
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfIPCache "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/go-openapi/runtime/middleware"
	"github.com/op/go-logging"
	"github.com/sirupsen/logrus"
)

// TriggerPolicyUpdates triggers policy updates for every daemon's endpoint.
// This is called after policy changes, but also after some changes in daemon
// configuration and endpoint labels.
// Returns a waiting group which signalizes when all endpoints are regenerated.
func (d *Daemon) TriggerPolicyUpdates(force bool) *sync.WaitGroup {
	if force {
		d.policy.BumpRevision() // force policy recalculation
		log.Debugf("Forced policy recalculation triggered")
	} else {
		log.Debugf("Full policy recalculation triggered")
	}
	return endpointmanager.TriggerPolicyUpdates(d)
}

// UpdateEndpointPolicyEnforcement returns whether policy enforcement needs to be
// enabled for the specified endpoint.
//
// Must be called with e.Consumable.Mutex and d.GetPolicyRepository().Mutex held.
func (d *Daemon) EnableEndpointPolicyEnforcement(e *endpoint.Endpoint) (ingress bool, egress bool) {
	// First check if policy enforcement should be enabled at the daemon level.
	switch policy.GetPolicyEnabled() {
	case option.AlwaysEnforce:
		// If policy enforcement is enabled for the daemon, then it has to be
		// enabled for the endpoint.
		return true, true
	case option.DefaultEnforcement:
		// Default mode means that if rules contain labels that match this endpoint,
		// then enable policy enforcement for this endpoint.
		// GH-1676: Could check e.Consumable instead? Would be much cheaper.
		return d.GetPolicyRepository().GetRulesMatching(e.SecurityIdentity.LabelArray)
	default:
		// If policy enforcement isn't enabled for the daemon we do not enable
		// policy enforcement for the endpoint.
		// This means that daemon policy enforcement mode is 'never', so no policy
		// enforcement should be applied to the specified endpoint.
		return false, false
	}
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
		verdict := api.Allowed.String()
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

func (d *Daemon) policyAdd(rules api.Rules, opts *AddOptions) (uint64, error) {
	d.policy.Mutex.Lock()
	defer d.policy.Mutex.Unlock()

	oldRules := api.Rules{}

	if opts != nil && opts.Replace {
		// Make copy of rules matching labels of new rules while
		// deleting them.
		for _, r := range rules {
			tmp := d.policy.SearchRLocked(r.Labels)
			if len(tmp) > 0 {
				d.policy.DeleteByLabelsLocked(r.Labels)
				oldRules = append(oldRules, tmp...)
			}
		}
	}

	rev, err := d.policy.AddListLocked(rules)
	if err != nil {
		metrics.PolicyImportErrors.Inc()
		// Restore old rules
		if len(oldRules) > 0 {
			if rev, err2 := d.policy.AddListLocked(oldRules); err2 != nil {
				log.WithError(err2).Error("Error while restoring old rules after adding of new rules failed")
				log.Error("--- INCONSISTENT STATE OF POLICY ---")
				return rev, err
			}
		}

		return rev, err
	}

	return rev, nil
}

// PolicyAdd adds a slice of rules to the policy repository owned by the
// daemon.  Policy enforcement is automatically enabled if currently disabled if
// k8s is not enabled. Otherwise, if k8s is enabled, policy is enabled on the
// pods which are selected. Eventual changes in policy rules are propagated to
// all locally managed endpoints.
func (d *Daemon) PolicyAdd(rules api.Rules, opts *AddOptions) (uint64, error) {
	log.WithField(logfields.CiliumNetworkPolicy, logfields.Repr(rules)).Debug("Policy Add Request")

	prefixes := policy.GetCIDRPrefixes(rules)
	log.WithField("prefixes", prefixes).Debug("Policy imported via API, found CIDR prefixes...")

	prefixIdentities, err := identity.AllocateCIDRIdentities(prefixes)
	if err != nil {
		metrics.PolicyImportErrors.Inc()
		return d.policy.GetRevision(), err
	}

	if err = ipcache.CheckPrefixes(bpfIPCache.IPCache, prefixes); err == nil {
		err = ipcache.UpsertIPNetsToKVStore(prefixes, prefixIdentities)
	}
	if err != nil {
		metrics.PolicyImportErrors.Inc()

		// Failed to update Prefix->ID mappings; don't leak identities
		identity.ReleaseSlice(prefixIdentities)
		return d.policy.GetRevision(), err
	}

	rev, err := d.policyAdd(rules, opts)
	if err != nil {
		// Don't leak identities allocated above.
		identity.ReleaseSlice(prefixIdentities)

		return 0, apierror.Error(PutPolicyFailureCode, err)
	}

	log.WithField(logfields.PolicyRevision, rev).Info("Policy imported via API, recalculating...")

	d.TriggerPolicyUpdates(false)

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
		return rev, apierror.New(DeletePolicyNotFoundCode, "policy not found")
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

	prefixIdentities, err := identity.LookupCIDRIdentities(prefixes)
	if err == nil {
		if err = identity.ReleaseSlice(prefixIdentities); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Labels: labels,
			}).Debug("Cannot delete identities for CIDR prefixes by labels")
		}

		if err = ipcache.DeleteIPNetsFromKVStore(prefixes); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Labels: labels,
			}).Debug("Could not delete prefix->Identity mappings during policy delete")
		}
	} else {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.Labels: labels,
		}).Debug("Cannot find identities for CIDR prefixes by labels")
	}

	d.TriggerPolicyUpdates(false)

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
		return apierror.Error(DeletePolicyFailureCode, err)
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

	var rules api.Rules
	if err := json.Unmarshal([]byte(*params.Policy), &rules); err != nil {
		return NewPutPolicyInvalidPolicy()
	}

	for _, r := range rules {
		if err := r.Sanitize(); err != nil {
			return apierror.Error(PutPolicyFailureCode, err)
		}
	}

	rev, err := d.PolicyAdd(rules, nil)
	if err != nil {
		return apierror.Error(PutPolicyFailureCode, err)
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
