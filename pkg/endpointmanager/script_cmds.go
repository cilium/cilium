// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
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
				// TODO: I think it's much easier to create an
				// Endpoint.DeepCopy() method where in this function, the new
				// endpoint will be a copy of the template endpoint and all of
				// the initialization of all the fakes/mocks will be done in
				// the code that defines the template endpoint (which is the
				// script test that calls this function).

				allArgs := []string(args)
				if len(allArgs) != 2 {
					return nil, fmt.Errorf("expected two args but got %v, see usage details", len(allArgs))
				}

				num, err := strconv.Atoi(allArgs[0])
				if err != nil {
					return nil, fmt.Errorf("atoi: %w", err)
				}

				var labelArr []labels.Label
				for _, s := range strings.Split(allArgs[1], ",") {
					labelArr = append(labelArr, labels.ParseLabel(s))
				}

				id := &identity.Identity{
					ID:         identity.NumericIdentity(num),
					Labels:     labels.FromSlice(labelArr),
					LabelArray: labels.LabelArray(labelArr),
				}

				// The following order of steps simulate adding an Endpoint the
				// way that the Agent does.
				ep := template.DeepCopy()
				err = epm.AddEndpoint(ep)
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
					return "", "", err
				}, nil
			},
		),
		"endpoint/regen-all": script.Command(
			script.CmdUsage{
				Summary: "Regenerate all Endpoints",
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
				wg := epm.RegenerateAllEndpoints(&regeneration.ExternalRegenerationMetadata{
					Reason:            "simulate regeneration of all endpoints from script command",
					RegenerationLevel: regeneration.RegenerateWithoutDatapath,
					ParentContext:     s.Context(),

					PolicyRevisionToWaitFor: uint64(rev),
				})
				return func(s *script.State) (stdout string, stderr string, err error) {
					wg.Wait()
					return "", "", nil
				}, nil
			},
		),
	}
}
