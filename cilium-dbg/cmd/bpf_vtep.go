// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/option"
)

// BPFVtepCmd represents the bpf command
var BPFVtepCmd = &cobra.Command{
	Use:   "vtep",
	Short: "Manage the VTEP mappings for IP/CIDR <-> VTEP MAC/IP",
}

func init() {
	BPFCmd.AddCommand(BPFVtepCmd)
}

func loadVTEPMask(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read agent runtime configuration: %w", err)
	}

	var config struct {
		VtepCidrMask netip.Addr
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse agent runtime configuration: %w", err)
	}
	if !config.VtepCidrMask.Is4() {
		return fmt.Errorf("VTEP CIDR Mask %q must be an IPv4 address", config.VtepCidrMask)
	}

	option.Config.VtepCidrMask = config.VtepCidrMask
	return nil
}
