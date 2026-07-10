// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"fmt"
	"os"

	"github.com/cilium/hive/script"

	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/source"
)

func PolicyImporterScriptCmds(p *Importer) map[string]script.Cmd {
	parse := func(s *script.State, args []string, del bool) (api.Rules, ipcachetypes.ResourceID, error) {
		if len(args) != 1 {
			return nil, "", fmt.Errorf("expected one arg but got %d, see usage details", len(args))
		}
		file := args[0]

		b, err := os.ReadFile(s.Path(file))
		if err != nil {
			b, err = os.ReadFile(file)
		}
		if err != nil {
			return nil, "", fmt.Errorf("failed to read %s: %w", file, err)
		}
		robj, err := testutils.DecodeObject(b)
		if err != nil {
			return nil, "", fmt.Errorf("decode object: %w", err)
		}

		var (
			rules      api.Rules
			resourceID ipcachetypes.ResourceID
		)
		switch policy := robj.(type) {
		case *v2.CiliumClusterwideNetworkPolicy:
			rules, err = policy.Parse(p.log, "")
			if err != nil {
				return nil, "", fmt.Errorf("ccnp parse: %w", err)
			}
			resourceID = ipcachetypes.NewResourceID(
				ipcachetypes.ResourceKindCCNP,
				policy.ObjectMeta.Namespace,
				policy.ObjectMeta.Name,
			)
		case *v2.CiliumNetworkPolicy:
			rules, err = policy.Parse(p.log, "")
			if err != nil {
				return nil, "", fmt.Errorf("cnp parse: %w", err)
			}
			resourceID = ipcachetypes.NewResourceID(
				ipcachetypes.ResourceKindCNP,
				policy.ObjectMeta.Namespace,
				policy.ObjectMeta.Name,
			)
		default:
			return nil, "", fmt.Errorf("unsupported policy type: %T", robj)
		}

		if del {
			return nil, resourceID, nil
		}
		return rules, resourceID, nil
	}

	return map[string]script.Cmd{
		"policy/import": script.Command(
			script.CmdUsage{
				Summary: "Import a policy change",
				Args:    "'policy'",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				rules, resourceID, err := parse(s, []string(args), false)
				if err != nil {
					return nil, err
				}
				dc := make(chan uint64, 1)
				p.UpdatePolicy(&policytypes.PolicyUpdate{
					Rules:    policyutils.RulesToPolicyEntries(rules),
					Source:   source.CustomResource,
					Resource: resourceID,
					DoneChan: dc,
				})
				return func(s *script.State) (stdout string, stderr string, err error) {
					rev := <-dc
					return fmt.Sprintf("Imported policy change, rev=%d\n", rev), "", nil
				}, nil
			},
		),
		"policy/remove": script.Command(
			script.CmdUsage{
				Summary: "Remove a policy",
				Args:    "'policy'",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				rules, resourceID, err := parse(s, []string(args), true)
				if err != nil {
					return nil, err
				}
				dc := make(chan uint64, 1)
				p.UpdatePolicy(&policytypes.PolicyUpdate{
					Rules:    policyutils.RulesToPolicyEntries(rules),
					Source:   source.CustomResource,
					Resource: resourceID,
					DoneChan: dc,
				})
				return func(s *script.State) (stdout string, stderr string, err error) {
					rev := <-dc
					return fmt.Sprintf("Removed policy, rev=%d\n", rev), "", nil
				}, nil
			},
		),
	}
}
