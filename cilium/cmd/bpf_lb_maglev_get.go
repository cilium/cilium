// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lbmap"
)

var bpfMaglevGetCmd = &cobra.Command{
	Use:     "get <service id>",
	Aliases: []string{"get"},
	Short:   "Get Maglev lookup table for given service by ID",
	PreRun:  requireServiceID,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb maglev get")

		arg, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil {
			Fatalf("Unable to parse %s: %s", args[0], err)
		}
		svcID := uint16(arg)

		backends, err := getMaglevServiceBackends(svcID)
		if err != nil {
			Fatalf("Unable to get Maglev backends for service %d: %s", svcID, err)
		}

		if len(backends) == 0 {
			Fatalf("No entry found for service %d", svcID)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(backends); err != nil {
				Fatalf("Unable to generate %s output: %s", command.OutputOptionString(), err)
			}
			return
		}

		TablePrinter("SVC ID", "LOOKUP TABLE", backends)
	},
}

// getMaglevServiceBackends queries the v4 and v6 Maglev maps for the backends
// of the given service ID.
func getMaglevServiceBackends(svcID uint16) (map[string][]string, error) {
	backends := make(map[string][]string)
	which := ""
	for _, mapName := range []string{lbmap.MaglevOuter4MapName, lbmap.MaglevOuter6MapName} {
		b, err := dumpMaglevServiceBackends(mapName, svcID)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, ebpf.ErrKeyNotExist) {
			// If the map or service ID don't exist, that is not an error.
			// The user is warned about no results by the command handler.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("map %s: %w", mapName, err)
		}
		if mapName == lbmap.MaglevOuter4MapName {
			which = "v4"
		} else {
			which = "v6"
		}
		backends[fmt.Sprintf("[%d]/%s", svcID, which)] = []string{b}
	}

	return backends, nil
}

// dumpMaglevServiceBackends looks up the given service ID in the Maglev map
// with the given name.
func dumpMaglevServiceBackends(mapName string, svcID uint16) (string, error) {
	m, err := lbmap.OpenMaglevOuterMap(mapName)
	if err != nil {
		return "", err
	}
	defer m.Close()

	inner, err := m.GetService(svcID)
	if err != nil {
		return "", err
	}

	return inner.DumpBackends()
}

func init() {
	bpfMaglevCmd.AddCommand(bpfMaglevGetCmd)
	command.AddOutputOption(bpfMaglevGetCmd)
}
