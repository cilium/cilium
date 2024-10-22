// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FlagsHooks = append(FlagsHooks, &operatorFlagsHooks{})
}

type operatorFlagsHooks struct{}

func (hook *operatorFlagsHooks) RegisterProviderFlag(_ *cobra.Command, _ *viper.Viper) {
}
