// Copyright 2019 Authors of Cilium
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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/cilium/pkg/health/probe/responder"
	"github.com/cilium/cilium/pkg/pidfile"

	flag "github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

func cancelOnSignal(cancel context.CancelFunc, sig ...os.Signal) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, sig...)
	go func() {
		<-c
		cancel()
	}()
}

func main() {
	var (
		pidfilePath string
		listen      int
	)
	flag.StringVar(&pidfilePath, "pidfile", "", "Write pid to the specified file")
	flag.IntVar(&listen, "listen", 4240, "Port on which the responder listens")
	flag.Parse()

	// Shutdown gracefully to halt server and remove pidfile
	ctx, cancel := context.WithCancel(context.Background())
	cancelOnSignal(cancel, unix.SIGINT, unix.SIGHUP, unix.SIGTERM, unix.SIGQUIT)

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
