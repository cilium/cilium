// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"github.com/cilium/hive/script"
)

func PolicyComputerScriptCmds(pc *IdentityPolicyComputer) map[string]script.Cmd {
	return map[string]script.Cmd{
		"policy/compute-all": script.Command(
			script.CmdUsage{
				Summary: "Recompute policy for all idenities",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				// TODO: Maybe add a flag to control whether to bump the revision or not.
				ws, err := pc.RecomputeIdentityPolicyForAllIdentities(pc.repo.GetRevision())
				if err != nil {
					return nil, err
				}
				return func(s *script.State) (stdout string, stderr string, err error) {
					_, err = ws.Wait(s.Context(), 0)
					return "", "", err
				}, nil
			},
		),
	}
}
