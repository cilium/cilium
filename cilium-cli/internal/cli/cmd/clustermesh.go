// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/clustermesh"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/status"
)

func newCmdClusterMesh() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clustermesh",
		Short: "Multi Cluster Management",
		Long:  ``,
	}

	cmd.AddCommand(
		newCmdClusterMeshStatus(),
		newCmdClusterMeshExternalWorkload(),
	)

	if utils.IsInHelmMode() {
		cmd.AddCommand(
			newCmdClusterMeshConnectWithHelm(),
			newCmdClusterMeshDisconnectWithHelm(),
			newCmdClusterMeshEnableWithHelm(),
			newCmdClusterMeshDisableWithHelm(),
		)
	} else {
		cmd.AddCommand(
			newCmdClusterMeshConnect(),
			newCmdClusterMeshDisconnect(),
			newCmdClusterMeshEnable(),
			newCmdClusterMeshDisable(),
		)
	}

	return cmd
}

func newCmdClusterMeshEnable() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable ClusterMesh ability in a cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.Enable(context.Background()); err != nil {
				fatalf("Unable to enable ClusterMesh: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&params.ServiceType, "service-type", "", "Type of Kubernetes service to expose control plane { ClusterIP | LoadBalancer | NodePort }")
	cmd.Flags().StringVar(&params.ApiserverImage, "apiserver-image", "", "Container image for clustermesh-apiserver")
	cmd.Flags().StringVar(&params.ApiserverVersion, "apiserver-version", "", "Container image version for clustermesh-apiserver")
	cmd.Flags().BoolVar(&params.CreateCA, "create-ca", true, "Automatically create CA if needed")
	cmd.Flags().StringSliceVar(&params.ConfigOverwrites, "config", []string{}, "clustermesh-apiserver config entries (key=value)")

	return cmd
}

func newCmdClusterMeshDisable() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable ClusterMesh ability in a cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.Disable(context.Background()); err != nil {
				fatalf("Unable to disable ClusterMesh: %s", err)
			}
			return nil
		},
	}

	return cmd
}

func newCmdClusterMeshConnect() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to a remote cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.Connect(context.Background()); err != nil {
				fatalf("Unable to connect cluster: %s", err)
			}
			return nil
		},
	}

	addCommonConnectFlags(cmd, &params)

	return cmd
}

func newCmdClusterMeshDisconnect() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "disconnect",
		Short: "Disconnect from a remote cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.Disconnect(context.Background()); err != nil {
				fatalf("Unable to disconnect cluster: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&params.DestinationContext, "destination-context", "", "Kubernetes configuration context of destination cluster")

	return cmd
}

func newCmdClusterMeshStatus() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show status of ClusterMesh",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			if params.Output == status.OutputJSON {
				// Write status log messages to stderr to make sure they don't
				// clutter JSON output.
				params.Writer = os.Stderr
			}

			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if _, err := cm.Status(context.Background()); err != nil {
				fatalf("Unable to determine status:  %s", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait until status is successful")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait")
	cmd.Flags().BoolVar(&params.SkipServiceCheck, "skip-service-check", false, "Do not require service IP of remote cluster to be available")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")

	return cmd
}

func newCmdClusterMeshExternalWorkload() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "external-workload",
		Aliases: []string{"vm"},
		Short:   "External Workload Management",
		Long:    ``,
	}

	cmd.AddCommand(
		newCmdExternalWorkloadCreate(),
		newCmdExternalWorkloadDelete(),
		newCmdExternalWorkloadInstall(),
		newCmdExternalWorkloadStatus(),
	)

	return cmd
}

func parseLabels(labels string) map[string]string {
	res := make(map[string]string)
	for _, str := range strings.Split(labels, ",") {
		str = strings.TrimSpace(str)
		i := strings.IndexByte(str, '=')
		if i < 0 {
			res[str] = ""
		} else {
			res[str[:i]] = str[i+1:]
		}
	}
	return res
}

func newCmdExternalWorkloadCreate() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stderr,
	}
	var labels string
	var namespace string

	cmd := &cobra.Command{
		Use:   "create <name...>",
		Short: "Create new external workloads",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			if labels != "" {
				params.Labels = parseLabels(labels)
			}
			if namespace != "" {
				if params.Labels == nil {
					params.Labels = make(map[string]string)
				}
				params.Labels[k8sConst.PodNamespaceLabel] = namespace
			}
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.CreateExternalWorkload(context.Background(), args); err != nil {
				fatalf("Unable to add external workloads: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&labels, "labels", "", "Comma separated list of labels for the external workload identity")
	cmd.Flags().StringVar(&params.IPv4AllocCIDR, "ipv4-alloc-cidr", "", "Unique IPv4 CIDR allocated for the external workload")
	cmd.Flags().StringVar(&params.IPv6AllocCIDR, "ipv6-alloc-cidr", "", "Unique IPv6 CIDR allocated for the external workload")

	return cmd
}

func newCmdExternalWorkloadDelete() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stderr,
	}

	cmd := &cobra.Command{
		Use:   "delete <name...>",
		Short: "Delete named external workloads",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.DeleteExternalWorkload(context.Background(), args); err != nil {
				fatalf("Unable to remove external workloads: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&params.All, "all", false, "Delete all resources if none are named")

	return cmd
}

func newCmdExternalWorkloadInstall() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stderr,
	}

	cmd := &cobra.Command{
		Use:   "install [output-file]",
		Short: "Creates a shell script to install external workloads",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			var writer io.Writer
			if len(args) > 0 {
				file, err := os.Create(args[0])
				if err != nil {
					fatalf("Unable to open file %s: %s", args[0], err)
				}
				defer func() {
					file.Chmod(0775)
					file.Close()
				}()
				writer = file
			} else {
				writer = os.Stdout
			}
			if err := cm.WriteExternalWorkloadInstallScript(context.Background(), writer); err != nil {
				fatalf("Unable to create external workload install script: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait until status is successful")
	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 15*time.Minute, "Maximum time to wait")
	cmd.Flags().StringSliceVar(&params.ConfigOverwrites, "config", []string{}, "Cilium agent config entries (key=value)")
	cmd.Flags().IntVar(&params.Retries, "retries", 4, "Number of Cilium agent start retries")

	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")

	return cmd
}

func newCmdExternalWorkloadStatus() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "status [name...]",
		Short: "Show status of external workloads",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace

			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.ExternalWorkloadStatus(context.Background(), args); err != nil {
				fatalf("Unable to determine status: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")

	return cmd
}

func newCmdClusterMeshEnableWithHelm() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable ClusterMesh ability in a cluster using Helm",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			ctx := context.Background()
			if err := clustermesh.EnableWithHelm(ctx, k8sClient, params); err != nil {
				fatalf("Unable to enable ClusterMesh: %s", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&params.EnableExternalWorkloads, "enable-external-workloads", false, "Enable support for external workloads, such as VMs")
	cmd.Flags().BoolVar(&params.EnableKVStoreMesh, "enable-kvstoremesh", false, "Enable kvstoremesh, an extension which caches remote cluster information in the local kvstore (Cilium >=1.14 only)")
	cmd.Flags().StringVar(&params.ServiceType, "service-type", "", "Type of Kubernetes service to expose control plane { LoadBalancer | NodePort | ClusterIP }")

	return cmd
}

func newCmdClusterMeshDisableWithHelm() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable ClusterMesh ability in a cluster using Helm",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			ctx := context.Background()
			if err := clustermesh.DisableWithHelm(ctx, k8sClient, params); err != nil {
				fatalf("Unable to disable ClusterMesh: %s", err)
			}
			return nil
		},
	}

	return cmd
}

func newCmdClusterMeshConnectWithHelm() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to a remote cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Namespace = namespace
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.ConnectWithHelm(context.Background()); err != nil {
				fatalf("Unable to connect cluster: %s", err)
			}
			return nil
		},
	}

	addCommonConnectFlags(cmd, &params)

	return cmd
}

func newCmdClusterMeshDisconnectWithHelm() *cobra.Command {
	var params = clustermesh.Parameters{
		Writer: os.Stdout,
	}

	cmd := &cobra.Command{
		Use:   "disconnect",
		Short: "Disconnect from a remote cluster",
		Run: func(cmd *cobra.Command, args []string) {
			params.Namespace = namespace
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			if err := cm.DisconnectWithHelm(context.Background()); err != nil {
				fatalf("Unable to disconnect clusters: %s", err)
			}
		},
	}
	cmd.Flags().StringVar(&params.DestinationContext, "destination-context", "", "Kubernetes configuration context of destination cluster")

	return cmd
}

func addCommonConnectFlags(cmd *cobra.Command, params *clustermesh.Parameters) {
	cmd.Flags().StringVar(&params.DestinationContext, "destination-context", "", "Kubernetes configuration context of destination cluster")
	cmd.Flags().StringSliceVar(&params.DestinationEndpoints, "destination-endpoint", []string{}, "IP of ClusterMesh service of destination cluster")
	cmd.Flags().StringSliceVar(&params.SourceEndpoints, "source-endpoint", []string{}, "IP of ClusterMesh service of source cluster")
}
