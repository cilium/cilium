// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dbg

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/go-openapi/strfmt"
	"github.com/spf13/cobra"
	netutil "k8s.io/apimachinery/pkg/util/net"

	clientapi "github.com/cilium/cilium/api/v1/kvstoremesh/client"
	"github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh"
)

var (
	client *clientapi.KvstoreMesh
)

var RootCmd = func() *cobra.Command {
	var host string

	cmd := &cobra.Command{
		Use:   "kvstoremesh-dbg",
		Short: "CLI for interacting with KVStoreMesh",

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
			cmd.SetContext(ctx)

			cfg := clientapi.DefaultTransportConfig().WithHost(host)
			client = clientapi.NewHTTPClientWithConfig(strfmt.Default, cfg)
		},
	}

	flags := cmd.PersistentFlags()
	flags.StringVarP(&host, "host", "H", kvstoremesh.DefaultAPIServeAddr, "URI to server-side API")

	return cmd
}()

func clientErrorHint(err error) error {
	if netutil.IsConnectionRefused(err) {
		return fmt.Errorf("is KVStoreMesh running and serving the API on %s?", kvstoremesh.DefaultAPIServeAddr)
	}
	return err
}
