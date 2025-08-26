// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ProviderFlagsHooks interface {
	RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper)
}
