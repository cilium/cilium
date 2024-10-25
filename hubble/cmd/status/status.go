// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package status

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/hubble/pkg/printer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

var formattingOpts struct {
	output string
}

// New status command.
func New(vp *viper.Viper) *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Display status of Hubble server",
		Long: `Display shows the status of the Hubble server. This is intended as a basic
connectivity health check.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			return runStatus(ctx, cmd.OutOrStdout(), hubbleConn)
		},
	}

	formattingFlags := pflag.NewFlagSet("Formatting", pflag.ContinueOnError)
	formattingFlags.StringVarP(
		&formattingOpts.output, "output", "o", "compact",
		`Specify the output format, one of:
 compact:  Compact output
 dict:     Status is shown as KEY:VALUE pair
 json:     JSON encoding
 table:    Tab-aligned columns
`)
	statusCmd.Flags().AddFlagSet(formattingFlags)

	// advanced completion for flags
	statusCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"compact",
			"dict",
			"json",
			"table",
		}, cobra.ShellCompDirectiveDefault
	})

	// add config.ServerFlags to the help template as these flags are used by
	// this command
	template.RegisterFlagSets(statusCmd, config.ServerFlags)

	return statusCmd
}

func runStatus(ctx context.Context, out io.Writer, conn *grpc.ClientConn) error {
	// get the standard GRPC health check to see if the server is up
	healthy, status, err := getHC(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed getting status: %w", err)
	}
	if formattingOpts.output == "compact" {
		fmt.Fprintf(out, "Healthcheck (via %s): %s\n", conn.Target(), status)
	}
	if !healthy {
		return errors.New("not healthy")
	}

	// if the server is up, lets try to get hubble specific status
	ss, err := getStatus(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to get hubble server status: %w", err)
	}

	var opts = []printer.Option{
		printer.Writer(out),
	}
	switch formattingOpts.output {
	case "compact":
		opts = append(opts, printer.Compact())
	case "dict":
		opts = append(opts, printer.Dict())
	case "json", "JSON", "jsonpb":
		opts = append(opts, printer.JSONPB())
	case "tab", "table":
		opts = append(opts, printer.Tab())
	default:
		return fmt.Errorf("invalid output format: %s", formattingOpts.output)
	}
	p := printer.New(opts...)
	if err := p.WriteServerStatusResponse(ss); err != nil {
		return err
	}
	return p.Close()
}

func getHC(ctx context.Context, conn *grpc.ClientConn) (healthy bool, status string, err error) {
	req := &healthpb.HealthCheckRequest{Service: v1.ObserverServiceName}
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, req)
	if err != nil {
		return false, "", err
	}
	if st := resp.GetStatus(); st != healthpb.HealthCheckResponse_SERVING {
		return false, fmt.Sprintf("Unavailable: %s", st), nil
	}
	return true, "Ok", nil
}

func getStatus(ctx context.Context, conn *grpc.ClientConn) (*observerpb.ServerStatusResponse, error) {
	req := &observerpb.ServerStatusRequest{}
	res, err := observerpb.NewObserverClient(conn).ServerStatus(ctx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}
