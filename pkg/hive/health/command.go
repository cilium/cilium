package health

import (
	"slices"
	"strings"

	healthPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"

	"github.com/spf13/pflag"
)

func healthCommands(db *statedb.DB, table statedb.Table[types.Status]) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"health": healthTreeCommand(db, table),
	})
}

func healthTreeCommand(db *statedb.DB, table statedb.Table[types.Status]) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List registered metrics",
			Args:    "[reporter-id-prefix]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("match", "m", "", "Output only health reports where the reporter ID path contains the substring")
				fs.StringArrayP("levels", "s", []string{types.LevelOK, types.LevelDegraded, types.LevelDegraded},
					"Output only health reports with the specified state (i.e. ok,degraded,stopped)")
			},
			Detail: []string{},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var prefix string
			if len(args) > 0 {
				prefix = args[0]
			}

			match, err := s.Flags.GetString("match")
			if err != nil {
				return nil, err
			}

			levels, err := s.Flags.GetStringArray("levels")
			if err != nil {
				return nil, err
			}

			for i := range levels {
				levels[i] = strings.ToLower(levels[i])
			}

			w := s.LogWriter()

			ss := []types.Status{}
			if prefix != "" {
				tx := db.ReadTxn()
				for status, _ := range table.Prefix(tx, PrimaryIndex.Query(types.HealthID(prefix))) {
					ss = append(ss, status)
				}
			} else {
				tx := db.ReadTxn()
				for status, _ := range table.All(tx) {
					if match != "" && !strings.Contains(status.ID.String(), match) {
						continue
					}

					if !slices.Contains(levels, strings.ToLower(status.Level.String())) {
						continue
					}

					ss = append(ss, status)
				}
			}
			healthPkg.GetAndFormatModulesHealth(w, ss, true, "")
			return nil, nil
		},
	)
}
