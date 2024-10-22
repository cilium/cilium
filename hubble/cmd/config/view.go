// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package config

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func newViewCommand(vp *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "view",
		Short: "Display merged configuration settings",
		Long:  "Display merged configuration settings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runView(cmd, vp)
		},
	}
}

func runView(cmd *cobra.Command, vp *viper.Viper) error {
	bs, err := yaml.Marshal(vp.AllSettings())
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}
	_, err = fmt.Fprint(cmd.OutOrStdout(), string(bs))
	return err
}
