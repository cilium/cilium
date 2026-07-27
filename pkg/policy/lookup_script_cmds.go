// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// identityLookuper looks up identities by their numeric ID. It is satisfied by
// cache.IdentityAllocator, but is defined locally to avoid importing
// pkg/identity/cache, which transitively pulls in dependencies that do not
// build on all platforms (e.g. renameio is unavailable on Windows) and would
// break the cilium-cli cross-platform build.
type identityLookuper interface {
	LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity
}

// LookupFlowScriptCmds returns script commands for looking up policy verdicts in tests.
func LookupFlowScriptCmds(
	logger *slog.Logger,
	repo PolicyRepository,
	idmgr identitymanager.IDManager,
	allocator identityLookuper,
) map[string]script.Cmd {
	return map[string]script.Cmd{
		"policy/lookup-flow": script.Command(
			script.CmdUsage{
				Summary: "Look up the policy verdict for a flow between two identities",
				Args:    "from-id to-id proto port",
				Flags: func(fs *pflag.FlagSet) {
					fs.Bool("egress", false, "Look up the egress policy verdict")
					fs.Bool("ingress", false, "Look up the ingress policy verdict")
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				egress, err := s.Flags.GetBool("egress")
				if err != nil {
					return nil, err
				}
				ingress, err := s.Flags.GetBool("ingress")
				if err != nil {
					return nil, err
				}
				switch {
				case egress && ingress:
					return nil, fmt.Errorf("only one of --egress or --ingress may be specified")
				case !egress && !ingress:
					return nil, fmt.Errorf("exactly one of --egress or --ingress must be specified")
				}

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

					decision := verdict.Egress
					if ingress {
						decision = verdict.Ingress
					}

					switch decision {
					case types.DecisionAllowed:
						return "allowed\n", "", nil
					case types.DecisionDenied:
						return "denied\n", "", nil
					default:
						direction := "egress"
						if ingress {
							direction = "ingress"
						}
						return "", "", fmt.Errorf("unexpected %s verdict: %v", direction, decision)
					}
				}, nil
			},
		),
	}
}
