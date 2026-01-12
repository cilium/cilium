// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FlagsHooks = append(FlagsHooks, &awsFlagsHooks{})
}

type awsFlagsHooks struct{}

func (hook *awsFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	vp.BindPFlags(flags)
}
