// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/models"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

// newLRPListCommand provides the "lrp/list" script command for script tests.
func newLRPListCommand(
	db *statedb.DB,
	lrps statedb.Table[*LocalRedirectPolicy],
	frontends statedb.Table[*lb.Frontend],
	backends statedb.Table[*lb.Backend],
	pods statedb.Table[k8sTables.LocalPod],
) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"lrp/list": script.Command(
			script.CmdUsage{
				Summary: "Write the LRP REST API model ('cilium-dbg lrp list')",
				Args:    "[output file]",
				Detail: []string{
					"Writes the LRP REST API model to either stdout or to a file.",
					"",
					"Each LRP will be shown as a line, followed by any mapped frontends with",
					"an indentation. For example:",
					"",
					"kube-system/nodelocaldns type=svc frontend-type=\"clusterIP + all svc ports\" service=kube-system/kube-dns",
					"  10.96.0.10:53/TCP => 10.244.0.225:53/TCP (kube-system/node-local-dns-1, active), 10.244.0.226:53/TCP (kube-system/node-local-dns-2, active)",
					"  10.96.0.10:53/UDP => 10.244.0.225:53/UDP (kube-system/node-local-dns-1, active), 10.244.0.226:53/UDP (kube-system/node-local-dns-2, active)",
					"",
					"Format is not guaranteed to be stable as this command is only",
					"for testing and debugging purposes.",
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				return func(s *script.State) (stdout string, stderr string, err error) {
					var lines []string

					for _, spec := range getLRPs(db.ReadTxn(), lrps, frontends, backends, pods) {
						lines = append(lines, formatLRPSpec(spec))
					}

					data := strings.Join(lines, "\n")

					if len(args) == 1 {
						err = os.WriteFile(s.Path(args[0]), []byte(data), 0644)
					} else {
						stdout = data
					}
					return
				}, nil
			},
		),
	})
}

func formatLRPSpec(spec *models.LRPSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%s type=%s frontend-type=%q", spec.Namespace, spec.Name, spec.LrpType, spec.FrontendType)
	if svcID := strings.Trim(spec.ServiceID, "/"); svcID != "" {
		fmt.Fprintf(&b, " service=%s", spec.ServiceID)
	}
	b.WriteByte('\n')
	for _, feM := range spec.FrontendMappings {
		bes := make([]string, 0, len(feM.Backends))
		for _, be := range feM.Backends {
			ip := "<nil>"
			if be.BackendAddress.IP != nil {
				ip = *be.BackendAddress.IP
			}
			bes = append(bes, fmt.Sprintf("%s:%d/%s (%s, %s)",
				ip, be.BackendAddress.Port, be.BackendAddress.Protocol, be.PodID, be.BackendAddress.State))
		}
		sort.Strings(bes)
		besStr := "(no backends)"
		if len(bes) > 0 {
			besStr = strings.Join(bes, ", ")
		}
		fe := feM.FrontendAddress
		fmt.Fprintf(&b, "  %s:%d/%s => %s\n", fe.IP, fe.Port, fe.Protocol, besStr)
	}
	return b.String()
}
