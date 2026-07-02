// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/hive/script"
	"github.com/davecgh/go-spew/spew"

	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func ScriptCmds(epm EndpointManager, template *endpoint.Endpoint) map[string]script.Cmd {
	return map[string]script.Cmd{
		"endpoint/create": script.Command(
			script.CmdUsage{
				Summary: "Create Endpoint",
				Args:    "'id' 'labels'",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				allArgs := []string(args)
				if len(allArgs) != 2 {
					return nil, fmt.Errorf("expected two args but got %v, see usage details", len(allArgs))
				}

				num, err := strconv.Atoi(allArgs[0])
				if err != nil {
					return nil, fmt.Errorf("atoi: %w", err)
				}

				var labelArr []labels.Label
				for s := range strings.SplitSeq(allArgs[1], ",") {
					labelArr = append(labelArr, labels.ParseLabel(s))
				}

				id := &identity.Identity{
					ID:         identity.NumericIdentity(num),
					Labels:     labels.FromSlice(labelArr),
					LabelArray: labels.LabelArray(labelArr),
				}

				// The following order of steps simulate adding an Endpoint the
				// way that the Agent does. Mark it fake so teardown skips the
				// host datapath, which the script harness does not provide.
				ep := template.CopyFromTemplate()
				ep.SetPropertyValue(endpointtypes.PropertyFakeEndpoint, true)
				err = epm.AddEndpoint(ep)
				if err != nil {
					return nil, err
				}
				_ = ep.UpdateLabels(s.Context(), labels.LabelSourceAny, id.Labels, nil, true)
				// Use RegenerateIfAlive to set the endpoint state to WaitingToRegenerate.
				_ = ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
					Reason:            "simulate Orchestrator",
					RegenerationLevel: regeneration.RegenerateWithDatapath,
					ParentContext:     s.Context(),
				})
				err = ep.WaitForFirstRegeneration(s.Context())
				if err != nil {
					return nil, err
				}
				<-ep.WaitForPolicyRevision(s.Context(), 1, nil)
				return func(s *script.State) (stdout string, stderr string, err error) {
					return strconv.FormatUint(uint64(ep.ID), 10), "", nil
				}, nil
			},
		),
		"endpoint/delete": script.Command(
			script.CmdUsage{
				Summary: "Delete an Endpoint",
				Args:    "id",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("expected one arg but got %v, see usage details", len(args))
				}
				id, err := strconv.ParseUint(args[0], 10, 16)
				if err != nil {
					return nil, fmt.Errorf("parse id: %w", err)
				}
				ep := epm.LookupCiliumID(uint16(id))
				if ep == nil {
					return nil, fmt.Errorf("endpoint %d not found", id)
				}
				return func(s *script.State) (stdout string, stderr string, err error) {
					if errs := epm.RemoveEndpoint(ep, endpoint.DeleteConfig{}); len(errs) > 0 {
						return "", "", fmt.Errorf("delete endpoint %d: %v", id, errs)
					}
					return "", "", nil
				}, nil
			},
		),
		"endpoint/list": script.Command(
			script.CmdUsage{
				Summary: "List all Endpoints",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				return func(s *script.State) (stdout string, stderr string, err error) {
					var sb strings.Builder
					sb.WriteRune('[')
					for _, ep := range epm.GetEndpointList(endpointapi.GetEndpointParams{}) {
						sb.WriteRune('{')
						sb.WriteString(spew.Sdump(
							"id", ep.ID,
							"identity", ep.Status.Identity,
							"status", ep.Status.Policy,
						))
						sb.WriteRune('}')
						sb.WriteRune(',')
						sb.WriteRune('\n')
					}
					sb.WriteString("]\n")
					return sb.String(), "", nil
				}, nil
			},
		),
		"endpoint/regen-all": script.Command(
			script.CmdUsage{
				Summary: "Regenerate all Endpoints",
				Args:    "policy-rev",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("expected one arg but got %v, see usage details", len(args))
				}
				rev, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("parse policy-rev: %w", err)
				}
				wg := epm.RegenerateAllEndpoints(&regeneration.ExternalRegenerationMetadata{
					Reason:            "simulate regeneration of all endpoints from script command",
					RegenerationLevel: regeneration.RegenerateWithoutDatapath,
					ParentContext:     s.Context(),

					PolicyRevisionToWaitFor: rev,
				})
				return func(s *script.State) (stdout string, stderr string, err error) {
					wg.Wait()
					return "", "", nil
				}, nil
			},
		),
		"endpoint/wait-for-policy-revision": script.Command(
			script.CmdUsage{
				Summary: "Wait for all Endpoints to have the given policy revision",
				Args:    "policy-rev",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				allArgs := []string(args)
				if len(allArgs) != 1 {
					return nil, fmt.Errorf("expected one arg but got %v, see usage details", len(allArgs))
				}
				rev, err := strconv.Atoi(allArgs[0])
				if err != nil {
					return nil, fmt.Errorf("atoi: %w", err)
				}
				return func(s *script.State) (stdout string, stderr string, err error) {
					err = epm.WaitForEndpointsAtPolicyRev(s.Context(), uint64(rev))
					if err != nil {
						return "", "", fmt.Errorf("error waiting for all endpoints: %w", err)
					}
					return "", "", nil
				}, nil
			},
		),
	}
}
