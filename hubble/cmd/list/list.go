// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/template"
)

var listOpts struct {
	output string
}

// New creates a new list command.
func New(vp *viper.Viper) *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List Hubble objects",
	}

	// add config.ServerFlags to the help template as these flags are used by
	// this command
	template.RegisterFlagSets(listCmd, config.ServerFlags)

	listCmd.AddCommand(
		newNodeCommand(vp),
		newNamespacesCommand(vp),
	)
	return listCmd
}

func jsonOutput(buf io.Writer, v any) error {
	bs, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(buf, string(bs))
	return err
}
