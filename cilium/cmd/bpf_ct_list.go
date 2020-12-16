// Copyright 2017-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	"github.com/spf13/cobra"
)

// bpfCtListCmd represents the bpf_ct_list command
var (
	bpfCtListCmd = &cobra.Command{
		Use:     "list ( <endpoint identifier> | global )",
		Aliases: []string{"ls"},
		Short:   "List connection tracking entries",
		PreRun:  requireEndpointIDorGlobal,
		Run: func(cmd *cobra.Command, args []string) {
			maps := getMaps(args[0])
			ctMaps := make([]interface{}, len(maps))
			for i, m := range maps {
				ctMaps[i] = m
			}
			common.RequireRootPrivilege("cilium bpf ct list")
			dumpCt(ctMaps, args[0])
		},
	}

	timeDiff                bool
	timeDiffClockSourceMode string
	timeDiffClockSourceHz   int64
)

func init() {
	bpfCtListCmd.Flags().BoolVarP(&timeDiff, "time-diff", "d", false, "print time difference for entries")
	bpfCtListCmd.Flags().StringVar(&timeDiffClockSourceMode, "time-diff-clocksource-mode", "", "manually set clock source mode (instead of contacting the server)")
	bpfCtListCmd.Flags().Int64Var(&timeDiffClockSourceHz, "time-diff-clocksource-hz", 250, "manually set clock source Hz")
	bpfCtCmd.AddCommand(bpfCtListCmd)
	command.AddJSONOutput(bpfCtListCmd)
}

func getMaps(eID string) []*ctmap.Map {
	if eID == "global" {
		return ctmap.GlobalMaps(true, true)
	}
	id, _ := strconv.Atoi(eID)
	return ctmap.LocalMaps(&dummyEndpoint{ID: id}, true, true)
}

func getClockSourceFromAgent() (*models.ClockSource, error) {
	params := daemon.NewGetHealthzParamsWithTimeout(5 * time.Second)
	brief := false
	params.SetBrief(&brief)
	resp, err := client.Daemon.GetHealthz(params)
	if err != nil {
		return nil, err
	}

	if resp.Payload.ClockSource == nil {
		return nil, errors.New("could not determine clocksource")
	}

	return resp.Payload.ClockSource, nil
}

func getClockSource() (*models.ClockSource, error) {
	switch timeDiffClockSourceMode {
	case "":
		return getClockSourceFromAgent()
	case models.ClockSourceModeKtime:
		return &models.ClockSource{
			Mode: models.ClockSourceModeKtime,
		}, nil

	case models.ClockSourceModeJiffies:
		if timeDiffClockSourceHz == 0 {
			return nil, errors.New("invalid HZ value")
		}
		return &models.ClockSource{
			Mode:  models.ClockSourceModeJiffies,
			Hertz: timeDiffClockSourceHz,
		}, nil

	default:
		return nil, errors.New("invalid clocksource")
	}
}

func doDumpEntries(m ctmap.CtMap) {
	var (
		out         string
		err         error
		clockSource *models.ClockSource
	)

	if timeDiff {
		clockSource, err = getClockSource()
		if err != nil {
			Fatalf("could not determine clocksource: %s", err)
		}
	}

	out, err = ctmap.DumpEntriesWithTimeDiff(m, clockSource)
	if err != nil {
		Fatalf("Error while dumping BPF Map: %s", err)
	}
	fmt.Println(out)
}

func dumpCt(maps []interface{}, args ...interface{}) {
	entries := make([]ctmap.CtMapRecord, 0)
	eID := args[0]

	for _, m := range maps {
		path, err := m.(ctmap.CtMap).Path()
		if err == nil {
			err = m.(ctmap.CtMap).Open()
		}
		if err != nil {
			if os.IsNotExist(err) {
				msg := "Unable to open %s: %s."
				if eID.(string) != "global" {
					msg = "Unable to open %s: %s: please try using \"cilium bpf ct list global\"."
				}
				fmt.Fprintf(os.Stderr, msg+" Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.(ctmap.CtMap).Close()
		// Plain output prints immediately, JSON output holds until it
		// collected values from all maps to have one consistent object
		if command.OutputJSON() {
			callback := func(key bpf.MapKey, value bpf.MapValue) {
				record := ctmap.CtMapRecord{Key: key.(ctmap.CtKey), Value: *value.(*ctmap.CtEntry)}
				entries = append(entries, record)
			}
			if err = m.(ctmap.CtMap).DumpWithCallback(callback); err != nil {
				Fatalf("Error while collecting BPF map entries: %s", err)
			}
		} else {
			doDumpEntries(m.(ctmap.CtMap))
		}
	}
	if command.OutputJSON() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
