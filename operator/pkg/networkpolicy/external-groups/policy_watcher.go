// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/operator/pkg/networkpolicy/external-groups/provider"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

type ToGroupCtlParams struct {
	cell.In

	Logger *slog.Logger
	JG     job.Group
	GM     ExternalGroupManager

	CNPResource  resource.Resource[*cilium_v2.CiliumNetworkPolicy]
	CCNPResource resource.Resource[*cilium_v2.CiliumClusterwideNetworkPolicy]
}

// policyExternalGroupController watches CNPs and CCNPs for changes,
// extracts the set of referenced external groups, and updates their
// entries in the external-group-controller.
type policyExternalGroupController struct {
	params ToGroupCtlParams
}

var gkCNP = schema.GroupKind{Group: cilium_v2.CustomResourceDefinitionGroup, Kind: cilium_v2.CNPKindDefinition}
var gkCCNP = schema.GroupKind{Group: cilium_v2.CustomResourceDefinitionGroup, Kind: cilium_v2.CCNPKindDefinition}

func registerPolicyToGroupController(params ToGroupCtlParams) *policyExternalGroupController {
	if !provider.Enabled() {
		return nil
	}

	pc := &policyExternalGroupController{
		params: params,
	}

	params.GM.RegisterResourceKind(gkCNP)
	params.GM.RegisterResourceKind(gkCCNP)

	params.JG.Add(job.Observer(
		"policy-cnp-external-group-watcher",
		pc.handleCNPEvent,
		params.CNPResource,
	))

	params.JG.Add(job.Observer(
		"policy-ccnp-external-group-watcher",
		pc.handleCCNPEvent,
		params.CCNPResource,
	))

	return pc
}

func (pc *policyExternalGroupController) handleCNPEvent(ctx context.Context, event resource.Event[*cilium_v2.CiliumNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()

	switch event.Kind {
	case resource.Sync:
		pc.params.GM.ResourceKindSynced(gkCNP)
	case resource.Delete:
		pc.params.GM.SetResourceGroups(gkCNP, event.Key.Namespace, event.Key.Name, nil)
	case resource.Upsert:
		pol := event.Object
		pc.setRules(gkCNP, pol.Namespace, pol.Name, pol.Spec, pol.Specs)
	}
	return nil
}

func (pc *policyExternalGroupController) handleCCNPEvent(ctx context.Context, event resource.Event[*cilium_v2.CiliumClusterwideNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()

	switch event.Kind {
	case resource.Sync:
		pc.params.GM.ResourceKindSynced(gkCCNP)
	case resource.Delete:
		pc.params.GM.SetResourceGroups(gkCCNP, event.Key.Namespace, event.Key.Name, nil)
	case resource.Upsert:
		pol := event.Object
		pc.setRules(gkCCNP, pol.Namespace, pol.Name, pol.Spec, pol.Specs)
	}
	return nil
}

func (pc *policyExternalGroupController) setRules(gk schema.GroupKind, namespace, name string, rule *api.Rule, rules []*api.Rule) {
	groups := extractGroups(rule)
	for _, r := range rules {
		groups = append(groups, extractGroups(r)...)
	}

	if len(groups) > 0 {
		pc.params.Logger.Info("Found ToGroups / FromGroups rules in policy",
			logfields.K8sAPIVersion, gk.Group,
			logfields.Kind, gk.Kind,
			logfields.K8sNamespace, namespace,
			logfields.Name, name,
			logfields.Count, len(groups))
	}

	pc.params.GM.SetResourceGroups(gk, namespace, name, groups)
}

func extractGroups(rule *api.Rule) []*api.Groups {
	if rule == nil {
		return nil
	}

	out := []*api.Groups{}
	for _, stanza := range rule.Egress {
		for i := range stanza.ToGroups {
			out = append(out, &stanza.ToGroups[i])
		}
	}
	for _, stanza := range rule.EgressDeny {
		for i := range stanza.ToGroups {
			out = append(out, &stanza.ToGroups[i])
		}
	}
	for _, stanza := range rule.Ingress {
		for i := range stanza.FromGroups {
			out = append(out, &stanza.FromGroups[i])
		}
	}
	for _, stanza := range rule.IngressDeny {
		for i := range stanza.FromGroups {
			out = append(out, &stanza.FromGroups[i])
		}
	}
	return out
}
