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

	"github.com/cilium/cilium-cli/connectivity"

	"github.com/spf13/cobra"
)

func newCmdConnectivity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connectivity",
		Short: "Connectivity troubleshooting",
		Long:  ``,
	}

	cmd.AddCommand(newCmdConnectivityCheck())

	return cmd
}

var params = connectivity.Parameters{
	Writer: os.Stdout,
}

func newCmdConnectivityCheck() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Validate connectivity in cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			check := connectivity.NewK8sConnectivityCheck(k8sClient, params)
			return check.Run(context.Background())
		},
	}

	cmd.Flags().BoolVar(&params.SingleNode, "single-node", false, "Limit to tests able to run on a single node")
	cmd.Flags().BoolVar(&params.PrintFlows, "print-flows", false, "Print flow logs for each test")
	cmd.Flags().DurationVar(&params.FlowSettleSleepDuration, "pre-flow-collect-sleep", 2*time.Second, "Wait time before collecting flows after testing connectivity")
	cmd.Flags().DurationVar(&params.PostTestSleepDuration, "post-test-sleep", 0, "Wait time after each test before next test starts")
	cmd.Flags().BoolVar(&params.ForceDeploy, "force-deploy", false, "Force re-deploying test artifacts")
	cmd.Flags().BoolVar(&params.Hubble, "hubble", true, "Automatically use Hubble for flow validation & troubleshooting")
	cmd.Flags().StringVar(&params.HubbleServer, "hubble-server", "localhost:4245", "Address of the Hubble endpoint for flow validation")
	cmd.Flags().StringVarP(&params.CiliumNamespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&params.MultiCluster, "multi-cluster", "", "Test across clusters to given context")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().StringSliceVar(&params.Tests, "test", []string{}, "Run a particular set of tests")

	return cmd
}
