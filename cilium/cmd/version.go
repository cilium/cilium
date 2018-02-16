// Copyright 2017 Authors of Cilium
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
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/version"

	"github.com/spf13/cobra"
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
	command.AddJSONOutput(versionCmd)
}

func getVersion(cmd *cobra.Command, args []string) {
	// -o argument is set
	if command.OutputJSON() {
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
