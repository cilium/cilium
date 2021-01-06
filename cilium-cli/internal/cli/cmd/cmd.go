// Copyright 2020 Authors of Cilium
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

	"github.com/cilium/cilium-cli/internal/k8s"

	"github.com/spf13/cobra"
)

var (
	contextName string
	k8sClient   *k8s.Client
)

func fatalf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func NewDefaultCiliumCommand() *cobra.Command {
	cmd := &cobra.Command{
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			c, err := k8s.NewClient(contextName)
			if err != nil {
				fatalf("Unable to create Kubernetes client: %s", err)
			}

			k8sClient = c
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		Use:   "cilium",
		Short: "Cilium Command Line Interface (CLI)",
		Long:  "CLI to interact with Cilium clusters",
	}

	cmd.AddCommand(newCmdContext())
	cmd.AddCommand(newCmdStatus())
	cmd.AddCommand(newCmdPolicy())
	cmd.AddCommand(newCmdConnectivity())
	cmd.AddCommand(newCmdInstall())
	cmd.AddCommand(newCmdUninstall())
	cmd.AddCommand(newCmdClusterMesh())
	cmd.AddCommand(newCmdHubble())
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")

	return cmd
}
