// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/maps/egressmap"
)

// Contains test commands used for hive-script-testing egressgw.
// These should *not* be included in the general egressgw hive cells.
//
// In general, it should be preferred to have output come from statedb
// tables as that provides a consistent interface for table writing
// and queries etc.
//
// This also attempts to maintain a separation between script testing
// code and egressgw internals.
var testCommandsCell = cell.Module("test-commands", "Test Commands",
	cell.Provide(scriptCommands),
)

type params struct {
	cell.In

	PolicyMap4 egressmap.PolicyMap4V2
	PolicyMap6 egressmap.PolicyMap6
}

func scriptCommands(p params) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"egress/policy-maps-dump": mapsDump(p),
	})
}

func mapsDump(p params) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump the egressgw BPF maps",
			Args:    "(output file)",
			Detail: []string{
				"This dumps the egressgw BPF maps either to stdout or to a file.",
				"Output is written in the format: key=value with spaces used to separate",
				"For example: source_ip=10.0.0.1 dest_cidr=99.0.0.0/24 egress_ip=100.0.0.1 gateway_ip=...",
				"Format is not guaranteed to be stable as this command is only",
				"for testing and debugging purposes.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				out := s.LogWriter()
				if len(args) > 0 {
					var err error
					out, err = os.Create(s.Path(args[0]))
					if err != nil {
						return "", "", err
					}
				}
				w := tabwriter.NewWriter(out, 5, 0, 3, ' ', 0)
				lines := []string{}
				p.PolicyMap4.IterateWithCallback(func(k *egressmap.EgressPolicyKey4, v *egressmap.EgressPolicyVal4V2) {
					lines = append(lines,
						fmt.Sprintf("source_ip=%s dest_cidr=%s egress_ip=%s egress_ifindex=%d gateway_ip=%s", k.SourceIP, k.DestCIDR, v.EgressIP, v.EgressIfindex, v.GetGatewayAddr()))
				})
				p.PolicyMap6.IterateWithCallback(func(k *egressmap.EgressPolicyKey6, v *egressmap.EgressPolicyVal6) {
					lines = append(lines,
						fmt.Sprintf("source_ip=%s dest_cidr=%s egress_ip=%s egress_ifindex=%d gateway_ip=%s", k.SourceIP, k.DestCIDR, v.EgressIP, v.EgressIfindex, v.GetGatewayAddr()))
				})

				sort.Strings(lines)
				for _, l := range lines {
					fmt.Fprintln(w, l)
				}
				w.Flush()

				return
			}, nil
		},
	)
}
