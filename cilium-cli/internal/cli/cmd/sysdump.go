// Copyright 2021 Authors of Cilium
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
	"io"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/cilium/cilium-cli/sysdump"
)

var (
	sysdumpOptions = sysdump.Options{
		LargeSysdumpAbortTimeout: sysdump.DefaultLargeSysdumpAbortTimeout,
		LargeSysdumpThreshold:    sysdump.DefaultLargeSysdumpThreshold,
		Writer:                   sysdump.DefaultWriter,
	}
)

func newCmdSysdump() *cobra.Command {
	cmd := &cobra.Command{
		Hidden: true,
		Use:    "sysdump",
		Short:  "Collects information required to troubleshoot issues with Cilium and Hubble",
		Long:   ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Silence klog to avoid displaying "throttling" messages - those are expected.
			klog.SetOutput(io.Discard)
			// Collect the sysdump.
			if err := sysdump.NewCollector(k8sClient, sysdumpOptions).Run(); err != nil {
				return fmt.Errorf("failed to collect sysdump: %v", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&contextName,
		"context", "",
		"Kubernetes configuration context")
	cmd.Flags().StringVar(&sysdumpOptions.CiliumLabelSelector,
		"cilium-label-selector", sysdump.DefaultCiliumLabelSelector,
		"The labels used to target Cilium pods")
	cmd.Flags().StringVar(&sysdumpOptions.CiliumNamespace,
		"cilium-namespace", sysdump.DefaultCiliumNamespace,
		"The namespace Cilium is running in")
	cmd.Flags().StringVar(&sysdumpOptions.CiliumOperatorLabelSelector,
		"cilium-operator-label-selector", sysdump.DefaultCiliumOperatorLabelSelector,
		"The labels used to target Cilium operator pods")
	cmd.Flags().StringVar(&sysdumpOptions.CiliumOperatorNamespace,
		"cilium-operator-namespace", sysdump.DefaultCiliumOperatorNamespace,
		"The namespace Cilium operator is running in")
	cmd.Flags().BoolVar(&sysdumpOptions.Debug,
		"debug", sysdump.DefaultDebug,
		"Whether to enable debug logging")
	cmd.Flags().StringVar(&sysdumpOptions.HubbleLabelSelector,
		"hubble-label-selector", sysdump.DefaultHubbleLabelSelector,
		"The labels used to target Hubble pods")
	cmd.Flags().StringVar(&sysdumpOptions.HubbleNamespace,
		"hubble-namespace", sysdump.DefaultHubbleNamespace,
		"The namespace Hubble is running in")
	cmd.Flags().StringVar(&sysdumpOptions.HubbleRelayLabelSelector,
		"hubble-relay-labels", sysdump.DefaultHubbleRelayLabelSelector,
		"The labels used to target Hubble Relay pods")
	cmd.Flags().StringVar(&sysdumpOptions.HubbleRelayNamespace,
		"hubble-relay-namespace", sysdump.DefaultHubbleRelayNamespace,
		"The namespace Hubble Relay is running in")
	cmd.Flags().StringVar(&sysdumpOptions.HubbleUILabelSelector,
		"hubble-ui-labels", sysdump.DefaultHubbleUILabelSelector,
		"The labels used to target Hubble UI pods")
	cmd.Flags().StringVar(&sysdumpOptions.HubbleUINamespace,
		"hubble-ui-namespace", sysdump.DefaultHubbleUINamespace,
		"The namespace Hubble UI is running in")
	cmd.Flags().Int64Var(&sysdumpOptions.LogsLimitBytes,
		"logs-limit-bytes", sysdump.DefaultLogsLimitBytes,
		"The limit on the number of bytes to retrieve when collecting logs")
	cmd.Flags().DurationVar(&sysdumpOptions.LogsSinceTime,
		"logs-since-time", sysdump.DefaultLogsSinceTime,
		"How far back in time to go when collecting logs")
	cmd.Flags().StringVar(&sysdumpOptions.NodeList,
		"node-list", sysdump.DefaultNodeList,
		"Comma-separated list of node IPs or names to filter pods for which to collect gops and logs")
	cmd.Flags().StringVar(&sysdumpOptions.OutputFileName,
		"output-filename", sysdump.DefaultOutputFileName,
		"The name of the resulting file (without extension)\n'<ts>' can be used as the placeholder for the timestamp")
	cmd.Flags().BoolVar(&sysdumpOptions.Quick,
		"quick", sysdump.DefaultQuick,
		"Whether to enable quick mode (i.e. skip collection of 'cilium-bugtool' output and logs)")
	cmd.Flags().IntVar(&sysdumpOptions.WorkerCount,
		"worker-count", sysdump.DefaultWorkerCount,
		"The number of workers to use")

	return cmd
}
