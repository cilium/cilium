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
	backends statedb.Table[*lb.Backend],
	pods statedb.Table[k8sTables.LocalPod],
) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"lrp/list": script.Command(
			script.CmdUsage{
				Summary: "Write the LRP REST API model ('cilium-dbg lrp list') to a file",
				Args:    "file",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("%w: output file needed", script.ErrUsage)
				}
				file, err := os.OpenFile(s.Path(args[0]), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					return nil, err
				}
				defer file.Close()
				for _, spec := range getLRPs(db.ReadTxn(), lrps, backends, pods) {
					fmt.Fprint(file, formatLRPSpec(spec))
				}
				return nil, nil
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
