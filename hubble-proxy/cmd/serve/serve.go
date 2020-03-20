// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package serve

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/cilium/pkg/hubble/proxy"
	"golang.org/x/sys/unix"

	"github.com/spf13/cobra"
)

// New creates a new serve command.
func New() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the gRPC proxy server",
		Long:  `Run the gRPC proxy server.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runServe()
		},
	}
}

func runServe() error {
	srv, err := proxy.NewServer()
	if err != nil {
		return fmt.Errorf("cannot create proxy server: %v", err)
	}

	if err := srv.Serve(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handleSignal(ctx, cancel)
	srv.Stop()
	return nil
}

func handleSignal(ctx context.Context, cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
	select {
	case <-ctx.Done():
	case <-sigs:
		cancel()
	}
}
