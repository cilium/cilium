// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/labels"
)

type CmdParams struct {
	cell.In

	EPL endpointmanager.EndpointsLookup
}

type PolicyCommands map[string]script.Cmd

func NewPolicyCommands(params CmdParams) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"policy/mapstate/entries": msEntriesCmd(params),
		"policy/mapstate/topk":    topKCmd(params),
	})
}

// autocompleteEndpoints returns a list of Endpoints that match the prefix of the argument.
//
// Accepted values are numeric endpoint IDs or <namespace/name>
func autocompleteEndpoints(params CmdParams) func(_ *script.State, _ []string, cur string) []string {
	return func(_ *script.State, _ []string, cur string) []string {
		eps := params.EPL.GetEndpoints()
		epNames := make([]string, 0, len(eps)*2)
		for _, ep := range eps {
			epNames = append(epNames, fmt.Sprintf("%d", ep.ID))
			if ep.K8sNamespace != "" && ep.K8sPodName != "" {
				epNames = append(epNames, fmt.Sprintf("%s/%s", ep.K8sNamespace, ep.K8sPodName))
			}
		}

		return filterPrefix(epNames, cur)
	}
}

// lookupEPs returns the set of endpoints that match the given specs,
// or all endpoints if empty
func lookupEPs(epl endpointmanager.EndpointsLookup, specs []string) ([]*endpoint.Endpoint, error) {
	if len(specs) == 0 {
		return epl.GetEndpoints(), nil
	}

	out := make([]*endpoint.Endpoint, 0, len(specs))
	for _, spec := range specs {
		if epid, err := strconv.Atoi(spec); err == nil {
			if epid > math.MaxUint16 || epid <= 0 {
				return nil, fmt.Errorf("invalid endpoint id %s", spec)
			}
			ep := epl.LookupCiliumID(uint16(epid))
			if ep == nil {
				return nil, fmt.Errorf("No endpoint with ID %d", epid)
			}
			out = append(out, ep)
		} else if strings.Contains(spec, "/") {
			eps := epl.GetEndpointsByPodName(spec)
			if len(eps) == 0 {
				return nil, fmt.Errorf("No endpoints with pod namespace/name %s", spec)
			}
			out = append(out, eps...)
		} else {
			return nil, fmt.Errorf("endpoint must either be numeric ID or <namespace/podname>s")
		}
	}
	return out, nil
}

func filterPrefix(vals []string, cur string) []string {
	return slices.DeleteFunc(vals, func(s string) bool {
		return !strings.HasPrefix(s, cur)
	})
}

type origin struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func summarizeOrigin(lbls labels.LabelArray) origin {
	kind := lbls.Get("io.cilium.k8s.policy.derived-from")
	ns := lbls.Get("k8s:io.cilium.k8s.policy.namespace")
	name := lbls.Get("k8s:io.cilium.k8s.policy.name")

	if kind != "" {
		return origin{
			Kind:      kind,
			Namespace: ns,
			Name:      name,
		}
	}

	from := lbls.Get("any:io.cilium.policy.derived-from")
	if from != "" {
		return origin{
			Kind: from,
		}
	}
	return origin{
		Kind: lbls.String(),
	}
}

func (o *origin) String() string {
	switch {
	case o.Namespace != "":
		return fmt.Sprintf("%s:%s/%s", o.Kind, o.Namespace, o.Name)
	case o.Name != "":
		return fmt.Sprintf("%s:%s", o.Kind, o.Name)
	default:
		return o.Kind
	}
}

func joinOrigins(os []origin) string {
	strs := make([]string, 0, len(os))
	for _, o := range os {
		strs = append(strs, o.String())
	}
	return strings.Join(strs, ",")
}
