// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	policyrest "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
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
}

func newPolicyAPIHandlers(params policyAPIHandlerParams) policyAPIHandlers {
	return policyAPIHandlers{
		PolicyGetPolicyHandler:          &getPolicyHandler{params},
		PolicyGetPolicySelectorsHandler: &getPolicySelectorsHandler{params},
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
