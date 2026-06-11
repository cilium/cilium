// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// LookupFlowScriptCmds returns script commands for looking up policy verdicts in tests.
func LookupFlowScriptCmds(
	logger *slog.Logger,
	repo PolicyRepository,
	idmgr identitymanager.IDManager,
	allocator cache.IdentityAllocator,
) map[string]script.Cmd {
	return map[string]script.Cmd{
		"policy/lookup-flow": script.Command(
			script.CmdUsage{
				Summary: "Look up the egress policy verdict for a flow between two identities",
				Args:    "from-id to-id proto port",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 4 {
					return nil, fmt.Errorf("expected 4 args (from-id to-id proto port), got %d", len(args))
				}

				fromID, err := strconv.ParseUint(args[0], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("parse from-id: %w", err)
				}
				toID, err := strconv.ParseUint(args[1], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("parse to-id: %w", err)
				}
				port, err := strconv.ParseUint(args[3], 10, 16)
				if err != nil {
					return nil, fmt.Errorf("parse port: %w", err)
				}

				proto, err := u8proto.ParseProtocol(args[2])
				if err != nil {
					return nil, fmt.Errorf("parse proto: %w", err)
				}

				from := allocator.LookupIdentityByID(s.Context(), identity.NumericIdentity(fromID))
				if from == nil {
					return nil, fmt.Errorf("identity %d not found", fromID)
				}
				to := allocator.LookupIdentityByID(s.Context(), identity.NumericIdentity(toID))
				if to == nil {
					return nil, fmt.Errorf("identity %d not found", toID)
				}

				flow := types.Flow{
					From:  from,
					To:    to,
					Proto: proto,
					Dport: uint16(port),
				}

				return func(s *script.State) (stdout string, stderr string, err error) {
					verdict, _, _, err := LookupFlow(logger, repo, idmgr, flow)
					if err != nil {
						return "", "", err
					}
					switch verdict.Egress {
					case types.DecisionAllowed:
						return "egress=allowed\n", "", nil
					case types.DecisionDenied:
						return "egress=denied\n", "", nil
					default:
						return "", "", fmt.Errorf("unexpected egress verdict: %v", verdict.Egress)
					}
				}, nil
			},
		),
	}
}
