// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
)

func newPeerCommand(vp *viper.Viper) *cobra.Command {
	peerCmd := &cobra.Command{
		Use:     "peers",
		Aliases: []string{"peer"},
		Short:   "Watch for Hubble peers updates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			return runPeer(ctx, peerpb.NewPeerClient(hubbleConn))
		},
	}
	// add config.ServerFlags to the help template as these flags are used by
	// this command
	template.RegisterFlagSets(peerCmd, config.ServerFlags)
	return peerCmd
}

func runPeer(ctx context.Context, client peerpb.PeerClient) error {
	b, err := client.Notify(ctx, &peerpb.NotifyRequest{})
	if err != nil {
		return err
	}
	for {
		resp, err := b.Recv()
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, context.Canceled):
			return nil
		case err == nil:
			processResponse(os.Stdout, resp)
		default:
			if status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}
	}
}

func processResponse(w io.Writer, resp *peerpb.ChangeNotification) {
	tlsServerName := ""
	if tls := resp.GetTls(); tls != nil {
		tlsServerName = fmt.Sprintf(" (TLS.ServerName: %s)", tls.GetServerName())
	}
	_, _ = fmt.Fprintf(w, "%-12s %s %s%s\n", resp.GetType(), resp.GetAddress(), resp.GetName(), tlsServerName)
}
