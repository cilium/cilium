// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_alibabacloud

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	FlagsHooks = append(FlagsHooks, &alibabaFlagsHooks{})
}

type alibabaFlagsHooks struct{}

func (hook *alibabaFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.String(operatorOption.AlibabaCloudVPCID, "", "Specific VPC ID for AlibabaCloud ENI. If not set use same VPC as operator")
	option.BindEnv(vp, operatorOption.AlibabaCloudVPCID)

	vp.BindPFlags(flags)
}
