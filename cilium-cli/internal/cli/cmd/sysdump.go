// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/cilium/cilium-cli/sysdump"
)

var (
	sysdumpOptions = sysdump.Options{
		LargeSysdumpAbortTimeout: sysdump.DefaultLargeSysdumpAbortTimeout,
		LargeSysdumpThreshold:    sysdump.DefaultLargeSysdumpThreshold,
		Writer:                   os.Stdout,
	}
)

func newCmdSysdump(hooks SysdumpHooks) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sysdump",
		Short: "Collects information required to troubleshoot issues with Cilium and Hubble",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Honor --namespace global flag in case it is set and --cilium-namespace is not set
			if sysdumpOptions.CiliumNamespace == "" && cmd.Flags().Changed("namespace") {
				sysdumpOptions.CiliumNamespace = namespace
			}
			// Silence klog to avoid displaying "throttling" messages - those are expected.
			klog.SetOutput(io.Discard)
			// Collect the sysdump.
			collector, err := sysdump.NewCollector(k8sClient, sysdumpOptions, time.Now(), version)
			if err != nil {
				return fmt.Errorf("failed to create sysdump collector: %w", err)
			}
			if err := hooks.AddSysdumpTasks(collector); err != nil {
				return fmt.Errorf("failed to add custom tasks: %w", err)
			}
			if err = collector.Run(); err != nil {
				return fmt.Errorf("failed to collect sysdump: %w", err)
			}
			return nil
		},
	}

	initSysdumpFlags(cmd, &sysdumpOptions, "", hooks)

	return cmd
}

func initSysdumpFlags(cmd *cobra.Command, options *sysdump.Options, optionPrefix string, hooks SysdumpHooks) {
	cmd.Flags().StringVar(&options.CiliumLabelSelector,
		optionPrefix+"cilium-label-selector", sysdump.DefaultCiliumLabelSelector,
		"The labels used to target Cilium pods")
	cmd.Flags().StringVar(&options.CiliumNamespace,
		optionPrefix+"cilium-namespace", "",
		"The namespace Cilium is running in. If not provided then the --namespace global flag is used (if provided)")
	cmd.Flags().StringVar(&options.CiliumOperatorNamespace,
		optionPrefix+"cilium-operator-namespace", "",
		"The namespace Cilium operator is running in")
	cmd.Flags().StringVar(&options.CiliumSPIRENamespace,
		optionPrefix+"cilium-spire-namespace", "",
		"The namespace Cilium SPIRE installation is running in")
	cmd.Flags().StringVar(&options.CiliumDaemonSetSelector,
		optionPrefix+"cilium-daemon-set-label-selector", sysdump.DefaultCiliumLabelSelector,
		"The labels used to target Cilium daemon set")
	cmd.Flags().StringVar(&options.CiliumEnvoyLabelSelector,
		optionPrefix+"cilium-envoy-label-selector", sysdump.DefaultCiliumEnvoyLabelSelector,
		"The labels used to target Cilium Envoy pods")
	cmd.Flags().StringVar(&options.CiliumHelmReleaseName,
		"cilium-helm-release-name", sysdump.DefaultCiliumHelmReleaseName,
		"The Cilium Helm release name for which to get values")
	cmd.Flags().StringVar(&options.CiliumOperatorLabelSelector,
		optionPrefix+"cilium-operator-label-selector", sysdump.DefaultCiliumOperatorLabelSelector,
		"The labels used to target Cilium operator pods")
	cmd.Flags().StringVar(&options.ClustermeshApiserverLabelSelector,
		optionPrefix+"clustermesh-apiserver-label-selector", sysdump.DefaultClustermeshApiserverLabelSelector,
		"The labels used to target 'clustermesh-apiserver' pods")
	cmd.Flags().StringVar(&options.CiliumNodeInitLabelSelector,
		optionPrefix+"cilium-node-init-selector", sysdump.DefaultCiliumNodeInitLabelSelector,
		"The labels used to target Cilium node init pods")
	cmd.Flags().StringVar(&options.CiliumSPIREAgentLabelSelector,
		optionPrefix+"cilium-spire-agent-selector", sysdump.DefaultCiliumSpireAgentLabelSelector,
		"The labels used to target Cilium spire-agent pods")
	cmd.Flags().StringVar(&options.CiliumSPIREServerLabelSelector,
		optionPrefix+"cilium-spire-server-selector", sysdump.DefaultCiliumSpireServerLabelSelector,
		"The labels used to target Cilium spire-server pods")
	cmd.Flags().BoolVar(&options.Debug,
		optionPrefix+"debug", sysdump.DefaultDebug,
		"Whether to enable debug logging")
	cmd.Flags().BoolVar(&options.Profiling,
		optionPrefix+"profiling", sysdump.DefaultProfiling,
		"Whether to enable scraping profiling data")
	cmd.Flags().StringArrayVar(&options.ExtraLabelSelectors,
		optionPrefix+"extra-label-selectors", nil,
		"Optional set of labels selectors used to target additional pods for log collection.")
	cmd.Flags().StringVar(&options.HubbleLabelSelector,
		optionPrefix+"hubble-label-selector", sysdump.DefaultHubbleLabelSelector,
		"The labels used to target Hubble pods")
	cmd.Flags().Int64Var(&options.HubbleFlowsCount,
		optionPrefix+"hubble-flows-count", sysdump.DefaultHubbleFlowsCount,
		"Number of Hubble flows to collect. Setting to zero disables collecting Hubble flows.")
	cmd.Flags().DurationVar(&options.HubbleFlowsTimeout,
		optionPrefix+"hubble-flows-timeout", sysdump.DefaultHubbleFlowsTimeout,
		"Timeout for collecting Hubble flows")
	cmd.Flags().StringVar(&options.HubbleRelayLabelSelector,
		optionPrefix+"hubble-relay-labels", sysdump.DefaultHubbleRelayLabelSelector,
		"The labels used to target Hubble Relay pods")
	cmd.Flags().StringVar(&options.HubbleUILabelSelector,
		optionPrefix+"hubble-ui-labels", sysdump.DefaultHubbleUILabelSelector,
		"The labels used to target Hubble UI pods")
	cmd.Flags().Int64Var(&options.LogsLimitBytes,
		optionPrefix+"logs-limit-bytes", sysdump.DefaultLogsLimitBytes,
		"The limit on the number of bytes to retrieve when collecting logs")
	cmd.Flags().DurationVar(&options.LogsSinceTime,
		optionPrefix+"logs-since-time", sysdump.DefaultLogsSinceTime,
		"How far back in time to go when collecting logs")
	cmd.Flags().StringVar(&options.NodeList,
		optionPrefix+"node-list", sysdump.DefaultNodeList,
		"Comma-separated list of node IPs or names to filter pods for which to collect gops and logs")
	cmd.Flags().StringVar(&options.OutputFileName,
		optionPrefix+"output-filename", sysdump.DefaultOutputFileName,
		"The name of the resulting file (without extension)\n'<ts>' can be used as the placeholder for the timestamp")
	cmd.Flags().BoolVar(&options.Quick,
		optionPrefix+"quick", sysdump.DefaultQuick,
		"Whether to enable quick mode (i.e. skip collection of 'cilium-bugtool' output and logs)")
	cmd.Flags().IntVar(&options.WorkerCount,
		optionPrefix+"worker-count", sysdump.DefaultWorkerCount,
		"The number of workers to use\nNOTE: There is a lower bound requirement on the number of workers for the sysdump operation to be effective. Therefore, for low values, the actual number of workers may be adjusted upwards.")
	cmd.Flags().StringArrayVar(&options.CiliumBugtoolFlags,
		optionPrefix+"cilium-bugtool-flags", nil,
		"Optional set of flags to pass to cilium-bugtool command.")
	cmd.Flags().BoolVar(&options.DetectGopsPID,
		optionPrefix+"detect-gops-pid", false,
		"Whether to automatically detect the gops agent PID.")
	cmd.Flags().StringVar(&options.CNIConfigDirectory,
		optionPrefix+"cni-config-directory", sysdump.DefaultCNIConfigDirectory,
		"Directory where CNI configs are located")
	cmd.Flags().StringVar(&options.CNIConfigMapName,
		optionPrefix+"cni-configmap-name", sysdump.DefaultCNIConfigMapName,
		"The name of the CNI config map")
	cmd.Flags().StringVar(&options.TetragonNamespace,
		optionPrefix+"tetragon-namespace", sysdump.DefaultTetragonNamespace,
		"The namespace Tetragon is running in")
	cmd.Flags().StringVar(&options.TetragonLabelSelector,
		optionPrefix+"tetragon-label-selector", sysdump.DefaultTetragonLabelSelector,
		"The labels used to target Tetragon pods")
	cmd.Flags().IntVar(&options.CopyRetryLimit,
		optionPrefix+"copy-retry-limit", sysdump.DefaultCopyRetryLimit,
		"Retry limit for file copying operations. If set to -1, copying will be retried indefinitely. Useful for collecting sysdump while on unreliable connection.")

	hooks.AddSysdumpFlags(cmd.Flags())
}
