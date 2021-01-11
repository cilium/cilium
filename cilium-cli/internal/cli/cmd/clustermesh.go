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

	"github.com/cilium/cilium-cli/clustermesh"

	"github.com/spf13/cobra"
)

func newCmdClusterMesh() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clustermesh",
		Short: "Multi Cluster Management",
		Long:  ``,
	}

	cmd.AddCommand(newCmdClusterMeshEnable())
	cmd.AddCommand(newCmdClusterMeshDisable())
	cmd.AddCommand(newCmdClusterMeshConnect())
	cmd.AddCommand(newCmdClusterMeshDisconnect())
	cmd.AddCommand(newCmdClusterMeshStatus())

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
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			return cm.Enable(context.Background())
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&params.ServiceType, "service-type", "", "Type of Kubernetes to expose control plane")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")

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
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			return cm.Disable(context.Background())
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")

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
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			return cm.Connect(context.Background())
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().StringVar(&params.DestinationContext, "destination-context", "", "Kubernetes configuration context of destination cluster")

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
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			return cm.Disconnect(context.Background())
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
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
			cm := clustermesh.NewK8sClusterMesh(k8sClient, params)
			return cm.Status(context.Background())
		},
	}

	cmd.Flags().StringVar(&params.Namespace, "namespace", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().BoolVar(&params.Wait, "wait", false, "Wait until status is successful")
	cmd.Flags().DurationVar(&params.WaitTime, "wait-duration", 15*time.Minute, "Maximum time to wait")

	return cmd
}
