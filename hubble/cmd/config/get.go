// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package config

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func newGetCommand(vp *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "get [KEY]",
		Short: "Get an individual value in the hubble config file",
		Long: "Get an individual value in the hubble config file.\n" +
			"If KEY is not provided, this command is equivalent to 'view'.",
		ValidArgs: vp.AllKeys(),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch len(args) {
			case 1:
				return runGet(cmd, vp, args[0])
			case 0:
				return runView(cmd, vp)
			default:
				return fmt.Errorf("invalid arguments: get requires exactly 0 or 1 argument: got '%s'", strings.Join(args, " "))
			}
		},
	}
}

func runGet(cmd *cobra.Command, vp *viper.Viper, key string) error {
	if !isKey(vp, key) {
		return fmt.Errorf("unknown key: %s", key)
	}

	// each viper key/val entry should be bound to a command flag
	flag := cmd.Flag(key)
	if flag == nil {
		return fmt.Errorf("key=%s not bound to a flag", key)
	}

	var val interface{}
	switch typ := flag.Value.Type(); typ {
	case "bool":
		val = vp.GetBool(key)
	case "duration":
		val = vp.GetDuration(key)
	case "int":
		val = vp.GetInt(key)
	case "string":
		val = vp.GetString(key)
	case "stringSlice":
		val = vp.GetStringSlice(key)
	default:
		val = vp.Get(key)
	}
	if bs, err := yaml.Marshal(val); err == nil {
		val = string(bs)
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), val)
	return err
}
