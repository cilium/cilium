// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Ensure build fails on versions of Go that are not supported by Cilium.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.20

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	flag "github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	healthDefaults "github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/health/probe/responder"
	"github.com/cilium/cilium/pkg/pidfile"
)

func main() {
	var (
		pidfilePath string
		listen      int
	)
	flag.StringVar(&pidfilePath, "pidfile", "", "Write pid to the specified file")
	flag.IntVar(&listen, "listen", healthDefaults.HTTPPathPort, "Port on which the responder listens")
	flag.Parse()

	// Shutdown gracefully to halt server and remove pidfile
	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGHUP, unix.SIGTERM, unix.SIGQUIT)

	srv := responder.NewServer(listen)
	defer srv.Shutdown()
	go func() {
		if err := srv.Serve(); err != nil {
			fmt.Fprintf(os.Stderr, "error while listening: %s\n", err.Error())
			cancel()
		}
	}()

	if pidfilePath != "" {
		defer pidfile.Clean()
		if err := pidfile.Write(pidfilePath); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write pidfile: %s: %s\n", pidfilePath, err.Error())
			os.Exit(1)
		}
	}

	<-ctx.Done()
}
