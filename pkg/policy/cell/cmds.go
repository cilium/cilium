package policycell

import (
	"fmt"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
)

func newCommands(repo *policy.Repository) hive.ScriptCmdsOut {
	pc := policyCommands{repo}
	return hive.NewScriptCmds(map[string]script.Cmd{
		"selectorcache": script.Command(
			script.CmdUsage{Summary: "Show selector cache"},
			pc.selectorCache,
		),
		"rules": script.Command(
			script.CmdUsage{Summary: "Show policy rules"},
			pc.rules,
		),
	})
}

type policyCommands struct {
	*policy.Repository
}

func (pc policyCommands) selectorCache(s *script.State, args ...string) (script.WaitFunc, error) {
	sc := pc.GetSelectorCache()
	w := tabwriter.NewWriter(s.LogWriter(), 5, 4, 3, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "Selector\tIdentities\tUsers\n")
	for _, mapping := range sc.GetModel() {
		fmt.Fprintf(w, "%s\t%v\t%d\n",
			mapping.Selector,
			mapping.Identities,
			mapping.Users,
		)
	}
	return nil, nil
}

func (pc policyCommands) rules(s *script.State, args ...string) (script.WaitFunc, error) {
	pc.Iterate(func(rule *api.Rule) {
		b, err := rule.MarshalJSON()
		if err != nil {
			s.Logf("MarshalJSON: %s\n", err)
		} else {
			s.Logf("%s\n", b)
		}
	})
	return nil, nil
}
