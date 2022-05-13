// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/version"
)

const notResponding = "Not responding"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		getVersion(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	command.AddOutputOption(versionCmd)
}

func getVersion(cmd *cobra.Command, args []string) {
	// -o argument is set
	if command.OutputOption() {
		data := struct {
			Client version.CiliumVersion
			Daemon version.CiliumVersion
		}{
			getClientVersionAsStruct(),
			getDaemonVersionAsStruct(),
		}
		if err := command.PrintOutput(data); err != nil {
			os.Exit(1)
		}
		return
	}
	// default output
	fmt.Printf("Client: %s\n", getClientVersionAsString())
	fmt.Printf("Daemon: %s\n", getDaemonVersionAsString())
}

func getClientVersionAsString() string {
	return version.Version
}

func getDaemonVersionAsString() string {
	resp, err := client.Daemon.GetDebuginfo(nil)
	if err != nil {
		return notResponding
	}
	return resp.Payload.CiliumVersion
}

func getClientVersionAsStruct() version.CiliumVersion {
	return version.GetCiliumVersion()
}

func getDaemonVersionAsStruct() version.CiliumVersion {
	data := getDaemonVersionAsString()
	if data == notResponding {
		return version.CiliumVersion{}
	}
	return version.FromString(data)
}
