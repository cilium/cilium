// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	FlagsHooks = append(FlagsHooks, &awsFlagsHooks{})
}

type awsFlagsHooks struct{}

func (hook *awsFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.Int32(operatorOption.AWSMaxResultsPerCall, 0, "Maximum results per AWS API call for DescribeNetworkInterfaces and DescribeSecurityGroups. Set to 0 to let AWS determine optimal page size (default). If set to 0 and AWS returns OperationNotPermitted errors, automatically switches to 1000 for all future requests")
	option.BindEnv(vp, operatorOption.AWSMaxResultsPerCall)

	// Deprecated: aws-pagination-enabled is deprecated in v1.19 and will be removed in v1.20.
	// Use --aws-max-results-per-call instead (true maps to 1000, false maps to 0).
	flags.Bool(operatorOption.AWSPaginationEnabled, true, "Deprecated: Use --aws-max-results-per-call instead")
	flags.MarkHidden(operatorOption.AWSPaginationEnabled)
	option.BindEnv(vp, operatorOption.AWSPaginationEnabled)

	vp.BindPFlags(flags)
}
