// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	healthPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/hive/health/types"
)

type healthCommandsParams struct {
	cell.In

	DB       *statedb.DB
	Statuses statedb.Table[types.Status]
	History  *healthHistory `optional:"true"`
}

func healthCommands(p healthCommandsParams) hive.ScriptCmdsOut {
	cmds := map[string]script.Cmd{
		"health":    healthTreeCommand(p.DB, p.Statuses),
		"health/ok": allOK(p.DB, p.Statuses),
	}
	if p.History != nil {
		cmds["health/history"] = healthHistoryCommand(p.History)
	}
	return hive.NewScriptCmds(cmds)
}

func healthTreeCommand(db *statedb.DB, table statedb.Table[types.Status]) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Log health reporter tree",
			Args:    "[reporter-id-prefix]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("match", "m", "", "Output only health reports where the reporter ID path contains the substring")
				fs.StringArrayP("levels", "s", []string{types.LevelOK, types.LevelDegraded, types.LevelDegraded},
					"Output only health reports with the specified state (i.e. ok,degraded,stopped)")
				fs.StringP("output", "o", "", "File to write output to")
			},
			Detail: []string{
				"Prints out a health reporter tree",
				"If passed prefix is not-empty then only nodes of this subtree",
				"will be displayed",
			},
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

			file, err := s.Flags.GetString("output")
			if err != nil {
				return nil, err
			}

			for i := range levels {
				levels[i] = strings.ToLower(levels[i])
			}

			w := s.LogWriter()
			if file != "" {
				p := s.Path(file)
				fd, err := os.Create(p)
				if err != nil {
					return nil, err
				}
				w = fd
			}

			ss := getHealth(db, table, prefix, match, levels)
			healthPkg.GetAndFormatModulesHealth(w, ss, true, "")

			if (prefix != "" || match != "") && len(ss) == 0 {
				return nil, errors.New("no health status found for the filter")
			}

			return nil, nil
		},
	)
}

func getHealth(db *statedb.DB, table statedb.Table[types.Status], prefix, match string, levels []string) []types.Status {
	ss := []types.Status{}
	if prefix != "" {
		tx := db.ReadTxn()
		for status := range table.Prefix(tx, PrimaryIndex.Query(types.HealthID(prefix))) {
			ss = append(ss, status)
		}
	} else {
		tx := db.ReadTxn()
		for status := range table.All(tx) {
			if match != "" && !strings.Contains(status.ID.String(), match) {
				continue
			}

			if !slices.Contains(levels, strings.ToLower(status.Level.String())) {
				continue
			}

			ss = append(ss, status)
		}
	}
	return ss
}

func allOK(db *statedb.DB, table statedb.Table[types.Status]) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Report and fail if there are degraded health reports",
			Args:    "[reporter-id-prefix]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("match", "m", "", "Output only health reports where the reporter ID path contains the substring")
			},
			Detail: []string{
				"Checks that all specified health reporters are healthy.\n",
				"If a non empty prefix is passed, only sub-trees of that .\n",
				"reporter will be checked\n",
			},
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

			w := s.LogWriter()

			ss := getHealth(db, table, prefix, match, []string{strings.ToLower(types.LevelDegraded)})
			healthPkg.GetAndFormatModulesHealth(w, ss, true, "")

			if len(ss) != 0 {
				return nil, fmt.Errorf("found %d degraded health reports", len(ss))
			}
			return nil, nil
		},
	)
}

func healthHistoryCommand(history *healthHistory) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Show health history",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "", "File to write output to")
			},
			Detail: []string{
				"Shows past degraded, stopped and closed health reports",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			file, err := s.Flags.GetString("output")
			if err != nil {
				return nil, err
			}
			w := s.LogWriter()
			if file != "" {
				p := s.Path(file)
				fd, err := os.Create(p)
				if err != nil {
					return nil, err
				}
				defer fd.Close()
				w = fd
			}
			err = history.replay(w)
			return nil, err
		},
	)
}
