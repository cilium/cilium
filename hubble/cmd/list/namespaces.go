// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
)

func newNamespacesCommand(vp *viper.Viper) *cobra.Command {
	namespacesCmd := &cobra.Command{
		Use:   "namespaces",
		Short: "List namespaces with recent flows",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			return runListNamespaces(ctx, cmd, hubbleConn)
		},
	}

	// formatting flags
	formattingFlags := pflag.NewFlagSet("Formatting", pflag.ContinueOnError)
	formattingFlags.StringVarP(
		&listOpts.output, "output", "o", "table",
		`Specify the output format, one of:
 json:     JSON encoding
 table:    Tab-aligned columns
 wide:     Tab-aligned columns with additional information`)
	namespacesCmd.Flags().AddFlagSet(formattingFlags)

	// advanced completion for flags
	namespacesCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"json",
			"table",
			"wide",
		}, cobra.ShellCompDirectiveDefault
	})

	template.RegisterFlagSets(namespacesCmd, formattingFlags, config.ServerFlags)
	return namespacesCmd
}

func runListNamespaces(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) error {
	req := &observerpb.GetNamespacesRequest{}
	res, err := observerpb.NewObserverClient(conn).GetNamespaces(ctx, req)
	if err != nil {
		return err
	}

	namespaces := res.GetNamespaces()
	switch listOpts.output {
	case "json":
		return jsonOutput(cmd.OutOrStdout(), namespaces)
	case "table", "wide":
		return namespaceTableOutput(cmd.OutOrStdout(), namespaces)
	default:
		return fmt.Errorf("unknown output format: %s", listOpts.output)
	}
}

func namespaceTableOutput(buf io.Writer, namespaces []*observerpb.Namespace) error {
	tw := tabwriter.NewWriter(buf, 2, 0, 3, ' ', 0)
	// header
	fmt.Fprint(tw, "NAMESPACE")
	if listOpts.output == "wide" {
		fmt.Fprint(tw, "\tCLUSTER")
	}
	fmt.Fprintln(tw)

	// contents
	for _, ns := range namespaces {
		fmt.Fprint(tw, ns.GetNamespace())
		if listOpts.output == "wide" && ns.GetCluster() != "" {
			fmt.Fprint(tw, "\t", ns.GetCluster())
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}
