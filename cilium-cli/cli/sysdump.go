// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/sysdump"
)

var (
	sysdumpOptions = sysdump.Options{
		LargeSysdumpAbortTimeout: sysdump.DefaultLargeSysdumpAbortTimeout,
		LargeSysdumpThreshold:    sysdump.DefaultLargeSysdumpThreshold,
		Writer:                   os.Stdout,
	}
)

func newCmdSysdump(hooks sysdump.Hooks) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sysdump",
		Short: "Collects information required to troubleshoot issues with Cilium and Hubble",
		Long:  ``,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Honor --namespace global flag in case it is set and --cilium-namespace is not set
			if sysdumpOptions.CiliumNamespace == "" && cmd.Flags().Changed("namespace") {
				sysdumpOptions.CiliumNamespace = namespace
			}
			if sysdumpOptions.CiliumOperatorNamespace == "" && cmd.Flags().Changed("namespace") {
				sysdumpOptions.CiliumOperatorNamespace = namespace
			}
			// Honor --helm-release-name global flag in case it is set and --cilium-helm-release-name is not set
			if sysdumpOptions.CiliumHelmReleaseName == "" && cmd.Flags().Changed("helm-release-name") {
				sysdumpOptions.CiliumHelmReleaseName = helmReleaseName
			}
			// Silence klog to avoid displaying "throttling" messages - those are expected.
			klog.SetOutput(io.Discard)
			// Collect the sysdump.
			collector, err := sysdump.NewCollector(k8sClient, sysdumpOptions, time.Now(), defaults.CLIVersion)
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

	sysdump.InitSysdumpFlags(cmd, &sysdumpOptions, "", hooks)

	return cmd
}
