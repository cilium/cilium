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
	"time"

	"github.com/cilium/cilium-cli/install"

	"github.com/spf13/cobra"
)

func newCmdInstall() *cobra.Command {
	var params = install.InstallParameters{Writer: os.Stdout}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Cilium in a Kubernetes cluster",
		Long: `Install Cilium in a Kubernetes cluster

Examples:
# Install Cilium in current Kubernetes context with default parameters
cilium install

# Install Cilium into Kubernetes context "kind-cluster1" and also set cluster
# name and ID to prepare for multi-cluster capabilties.
cilium install --context kind-cluster1 --cluster-id 1 --cluster-name cluster1
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			installer := install.NewK8sInstaller(k8sClient, params)
			cmd.SilenceUsage = true
			return installer.Install(context.Background())
		},
	}

	cmd.Flags().StringVarP(&params.Namespace, "namespace", "n", "kube-system", "Namespace to install Cilium into")
	cmd.Flags().StringVar(&params.ClusterName, "cluster-name", "", "Name of the cluster")
	cmd.Flags().StringSliceVar(&params.DisableChecks, "disable-check", []string{}, "Disable a particular validation check")
	cmd.Flags().StringVar(&params.Version, "version", "", "Cilium version to install")
	cmd.Flags().StringVar(&params.DatapathMode, "datapath-mode", "", "Datapath mode to use")
	cmd.Flags().StringVar(&params.NativeRoutingCIDR, "native-routing-cidr", "", "CIDR within which native routing is possible")
	cmd.Flags().IntVar(&params.ClusterID, "cluster-id", 0, "Unique cluster identifier for multi-cluster")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().StringVar(&params.InheritCA, "inherit-ca", "", "Inherit/import CA from another cluster")
	cmd.Flags().StringVar(&params.KubeProxyReplacement, "kube-proxy-replacement", "probe", "Enable/disable kube-proxy replacement { disabled | probe | strict }")
	cmd.Flags().BoolVar(&params.Wait, "wait", true, "Wait for status to report success (no errors)")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait for status")
	cmd.Flags().StringVar(&params.Azure.ResourceGroupName, "azure-resource-group", "", "Azure resource group name the cluster is in")
	cmd.Flags().BoolVar(&params.RestartUnmanagedPods, "restart-unmanaged-pods", true, "Restart pods which are not being managed by Cilium")
	cmd.Flags().BoolVar(&params.Encryption, "encryption", false, "Enable encryption of all workloads traffic")
	cmd.Flags().BoolVar(&params.NodeEncryption, "node-encryption", false, "Enable encryption of all node to node traffic")
	cmd.Flags().StringVar(&params.Azure.TenantID, "azure-tenant-id", "", "Azure tenant ID")
	cmd.Flags().StringVar(&params.Azure.ClientID, "azure-client-id", "", "Azure client (application) ID")
	cmd.Flags().StringVar(&params.Azure.ClientSecret, "azure-client-secret", "", "Azure client secret")

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

	cmd.Flags().StringVarP(&params.Namespace, "namespace", "n", "kube-system", "Namespace to uninstall Cilium from")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")

	return cmd
}
