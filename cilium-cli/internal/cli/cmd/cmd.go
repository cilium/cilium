// Copyright 2020-2021 Authors of Cilium
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
	"os"

	"github.com/cilium/cilium-cli/internal/k8s"

	"github.com/spf13/cobra"
)

var (
	contextName string
	k8sClient   *k8s.Client
)

func NewDefaultCiliumCommand() *cobra.Command {
	cmd := &cobra.Command{
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			c, err := k8s.NewClient(contextName, "")
			if err != nil {
				fatalf("Unable to create Kubernetes client: %s", err)
			}

			k8sClient = c
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		Use:   "cilium",
		Short: "Cilium provides eBPF-based Networking, Security, and Observability for Kubernetes",
		Long: `CLI to install, manage, & troubleshooting Cilium clusters running Kubernetes.

Cilium is a CNI for Kubernetes to provide secure network connectivity and
load-balancing with excellent visibility using eBPF

Examples:
# Install Cilium in current Kubernetes context
cilium install

# Check status of Cilium
cilium status

# Enable the Hubble observability layer
cilium hubble enable

# Perform a connectivity test
cilium connectivity test`,
	}

	cmd.AddCommand(
		newCmdClusterMesh(),
		newCmdConfig(),
		newCmdCompletion(),
		newCmdConnectivity(),
		newCmdContext(),
		newCmdHubble(),
		newCmdInstall(),
		newCmdPolicy(),
		newCmdStatus(),
		newCmdUninstall(),
	)
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	return cmd
}
