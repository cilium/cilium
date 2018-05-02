// Copyright 2017 Authors of Cilium
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
	"net"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/pkg/apisocket"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	gops "github.com/google/gops/agent"
	"github.com/spf13/cobra"
)

var log = logging.DefaultLogger

const targetName = "cilium-node-monitor"

var (
	rootCmd = &cobra.Command{
		Use:   targetName,
		Short: "Cilium node monitor",
		Long:  `Agent for reading the events from the BPF datapath.`,
		Run: func(cmd *cobra.Command, args []string) {
			runNodeMonitor()
		},
	}
	npages int
)

func init() {
	rootCmd.Flags().IntVar(&npages, "num-pages", 64, "Number of pages for ring buffer")
}

func execute() {
	if err := rootCmd.Execute(); err != nil {
		log.WithError(err)
		os.Exit(-1)
	}
}

func main() {
	execute()
}

func runNodeMonitor() {
	eventSockPath := path.Join(defaults.RuntimePath, defaults.EventsPipe)
	pipe, err := os.OpenFile(eventSockPath, os.O_RDONLY, 0600)
	if err != nil {
		log.WithError(err).Fatalf("Unable to open named pipe %s for reading", eventSockPath)
	}
	defer pipe.Close() // stop recieving agent events

	scopedLog := log.WithField(logfields.Path, defaults.MonitorSockPath)
	// Open socket for using gops to get stacktraces of the agent.
	if err := gops.Listen(gops.Options{}); err != nil {
		scopedLog.WithError(err).Fatal("Unable to start gops")
	}

	common.RequireRootPrivilege(targetName)
	os.Remove(defaults.MonitorSockPath)
	server, err := net.Listen("unix", defaults.MonitorSockPath)
	if err != nil {
		scopedLog.WithError(err).Fatal("Cannot listen on socket")
	}
	defer server.Close() // Do not accept new connections

	if os.Getuid() == 0 {
		err := apisocket.SetDefaultPermissions(defaults.MonitorSockPath)
		if err != nil {
			scopedLog.WithError(err).Fatal("Cannot set default permissions on socket")
		}
	}
	log.Infof("Serving cilium node monitor at unix://%s", defaults.MonitorSockPath)

	mainCtx, mainCtxCancel := context.WithCancel(context.Background())
	defer mainCtxCancel() // Signal a shutdown to spawned goroutines

	m := Monitor{}
	if err := m.Init(mainCtx, npages, pipe, server); err != nil {
		log.WithError(err).Fatal("Error initialising monitor handlers")
	}

	shutdownChan := make(chan os.Signal)
	signal.Notify(shutdownChan, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGTERM, syscall.SIGINT)
	sig := <-shutdownChan
	log.WithField(logfields.Signal, sig).Info("Exiting due to signal")
}
