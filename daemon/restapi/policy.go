// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"encoding/json"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	policyrest "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var policyAPICell = cell.Module(
	"policy-api",
	"Policy updates via REST API",

	cell.Provide(newPolicyAPIHandlers),
)

type policyAPIHandlerParams struct {
	cell.In

	Log *slog.Logger

	Repo     policy.PolicyRepository
	Importer policycell.PolicyImporter
}

type policyAPIHandlers struct {
	cell.Out

	PolicyGetPolicyHandler          policyrest.GetPolicyHandler
	PolicyGetPolicySelectorsHandler policyrest.GetPolicySelectorsHandler
	PolicyPutPolicyHandler          policyrest.PutPolicyHandler
	PolicyDeletePolicyHandler       policyrest.DeletePolicyHandler
}

func newPolicyAPIHandlers(params policyAPIHandlerParams) policyAPIHandlers {
	return policyAPIHandlers{
		PolicyGetPolicyHandler:          &getPolicyHandler{params},
		PolicyGetPolicySelectorsHandler: &getPolicySelectorsHandler{params},
		PolicyPutPolicyHandler:          &putPolicyHandler{params},
		PolicyDeletePolicyHandler:       &deletePolicyHandler{params},
	}
}

type getPolicyHandler struct {
	policyAPIHandlerParams
}

func (h *getPolicyHandler) Handle(params policyrest.GetPolicyParams) middleware.Responder {
	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	ruleList, rev := h.Repo.Search(lbls)

	// Error if labels have been specified but no entries found, otherwise,
	// return empty list
	if len(ruleList) == 0 && len(lbls) != 0 {
		return policyrest.NewGetPolicyNotFound()
	}

	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(ruleList),
	}

	h.Log.Debug("Policy Get Request", logfields.PolicyRevision, policy.Revision)

	return policyrest.NewGetPolicyOK().WithPayload(policy)
}

type getPolicySelectorsHandler struct {
	policyAPIHandlerParams
}

func (h *getPolicySelectorsHandler) Handle(params policyrest.GetPolicySelectorsParams) middleware.Responder {
	return policyrest.NewGetPolicySelectorsOK().WithPayload(h.Repo.GetSelectorCache().GetModel())
}

type putPolicyHandler struct {
	policyAPIHandlerParams
}

func (h *putPolicyHandler) Handle(params policyrest.PutPolicyParams) middleware.Responder {
	var rules policyapi.Rules
	if err := json.Unmarshal([]byte(params.Policy), &rules); err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		return policyrest.NewPutPolicyInvalidPolicy()
	}

	for _, r := range rules {
		if err := r.Sanitize(); err != nil {
			metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
			return api.Error(policyrest.PutPolicyFailureCode, err)
		}
	}

	replace := false
	if params.Replace != nil {
		replace = *params.Replace
	}
	replaceWithLabels := labels.ParseSelectLabelArrayFromArray(params.ReplaceWithLabels)

	dc := make(chan uint64, 1)
	h.Importer.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:               rules,
		ReplaceByLabels:     replace,
		ReplaceWithLabels:   replaceWithLabels,
		Source:              source.LocalAPI,
		DoneChan:            dc,
		ProcessingStartTime: time.Now(),
	})
	rev := <-dc

	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()

	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(rules),
	}
	return policyrest.NewPutPolicyOK().WithPayload(policy)
}

type deletePolicyHandler struct {
	policyAPIHandlerParams
}

func (h *deletePolicyHandler) Handle(params policyrest.DeletePolicyParams) middleware.Responder {
	lbls := labels.ParseSelectLabelArrayFromArray(params.Labels)
	dc := make(chan uint64, 1)
	h.Importer.UpdatePolicy(&policytypes.PolicyUpdate{
		ReplaceWithLabels:   lbls,
		Source:              source.LocalAPI,
		DoneChan:            dc,
		ProcessingStartTime: time.Now(),
	})
	<-dc

	ruleList, rev := h.Repo.Search(labels.LabelArray{})
	policy := &models.Policy{
		Revision: int64(rev),
		Policy:   policy.JSONMarshalRules(ruleList),
	}
	return policyrest.NewDeletePolicyOK().WithPayload(policy)
}
