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
	"context"
	"os"

	"github.com/cilium/cilium-cli/install"

	"github.com/spf13/cobra"
)

func newCmdInstall() *cobra.Command {
	var params = install.InstallParameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Cilium",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			installer := install.NewK8sInstaller(k8sClient, params)
			cmd.SilenceUsage = true
			return installer.Install(context.Background())
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace to install Cilium into")
	cmd.Flags().StringVar(&params.ClusterName, "cluster-name", "", "Name of the cluster")
	cmd.Flags().StringSliceVar(&params.DisableChecks, "disable-check", []string{}, "Disable a particular validation check")
	cmd.Flags().StringVar(&params.Version, "version", "", "Cilium version to install")
	cmd.Flags().StringVar(&params.DatapathMode, "datapath-mode", "", "Cilium version to install")

	return cmd
}

func newCmdUninstall() *cobra.Command {
	var params = install.UninstallParameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Cilium",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			uninstaller := install.NewK8sUninstaller(k8sClient, params)
			return uninstaller.Uninstall(context.Background())
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace to install Cilium into")

	return cmd
}
