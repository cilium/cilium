// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// bpfCtListCmd represents the bpf_ct_list command
var (
	bpfCtListCmd = &cobra.Command{
		Use:     "list ( global | endpoint | cluster ) [identifier]",
		Aliases: []string{"ls"},
		Short:   "List connection tracking entries",
		PreRun:  requireEndpointIDorGlobal,
		Run: func(cmd *cobra.Command, args []string) {
			t, id, err := parseArgs(args)
			if err != nil {
				cmd.PrintErrf("Invalid argument: %s", err.Error())
				return
			}
			maps := getMaps(t, id)
			ctMaps := make([]interface{}, len(maps))
			for i, m := range maps {
				ctMaps[i] = m
			}
			common.RequireRootPrivilege("cilium bpf ct list")
			dumpCt(ctMaps, t)
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
	command.AddOutputOption(bpfCtListCmd)
}

func parseArgs(args []string) (string, uint32, error) {
	if len(args) == 0 {
		return "", 0, fmt.Errorf("no CT map type provided")
	}

	t := args[0]
	switch t {
	case "global":
		return t, 0, nil
	case "endpoint":
		if len(args) != 2 {
			return "", 0, fmt.Errorf("missing endpointID")
		}
		id, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return "", 0, fmt.Errorf("invalid endpointID: %w", err)
		}
		return t, uint32(id), nil
	case "cluster":
		if len(args) != 2 {
			return "", 0, fmt.Errorf("missing clusterID")
		}
		id, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return "", 0, fmt.Errorf("invalid clusterID: %w", err)
		}
		return t, uint32(id), nil
	default:
		return "", 0, fmt.Errorf("unknown type %s", args[0])
	}
}

func getMaps(t string, id uint32) []*ctmap.Map {
	if t == "global" {
		return ctmap.GlobalMaps(true, getIpv6EnableStatus())
	}
	if t == "endpoint" {
		return ctmap.LocalMaps(&dummyEndpoint{ID: int(id)}, true, true)
	}
	if t == "cluster" {
		ctmap.InitPerClusterCTMaps(ctmap.PerClusterCTOuterMapPrefix, true, getIpv6EnableStatus())
		return ctmap.PerClusterCTMaps.GetClusterCTMaps(id)
	}
	return []*ctmap.Map{}
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

	t := args[0].(string)

	for _, m := range maps {
		m := m.(ctmap.CtMap)

		path, err := m.Path()
		if err == nil {
			err = m.Open()
		}
		if err != nil {
			if os.IsNotExist(err) {
				msg := "Unable to open %s: %s."
				if t != "global" {
					msg = "Unable to open %s: %s: please try using \"cilium bpf ct list global\"."
				}
				fmt.Fprintf(os.Stderr, msg+" Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.Close()
		// Plain output prints immediately, JSON/YAML output holds until it
		// collected values from all maps to have one consistent object
		if command.OutputOption() {
			callback := func(key bpf.MapKey, value bpf.MapValue) {
				record := ctmap.CtMapRecord{Key: key.(ctmap.CtKey), Value: *value.(*ctmap.CtEntry)}
				entries = append(entries, record)
			}
			if err = m.DumpWithCallback(callback); err != nil {
				Fatalf("Error while collecting BPF map entries: %s", err)
			}
		} else {
			doDumpEntries(m)
		}
	}
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
