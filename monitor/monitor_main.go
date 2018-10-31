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

package monitor

import (
	"context"
	"net"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	gops "github.com/google/gops/agent"
	"github.com/spf13/cobra"
)

var (
	log              = logging.DefaultLogger.WithField(logfields.LogSubsys, targetName)
	monitorSingleton *Monitor
)

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

	// bpfRoot is the path to the BPF mount. This can be non-default if
	// cilium-agent mounts bpf at an alternate location.
	bpfRoot string
)

func init() {
	rootCmd.Flags().IntVar(&npages, "num-pages", 64, "Number of pages for ring buffer")
	rootCmd.Flags().StringVar(&bpfRoot, "bpf-root", "/sys/fs/bpf", "Path to the root of the bpf mount")
}

// Execute is an entry point for node monitor
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.WithError(err).Error("Monitor failed")
		os.Exit(-1)
	}
}

// buildServerOrExit opens a listener socket at path. It exits with logging on
// all errors.
func buildServerOrExit(path string) net.Listener {
	scopedLog := log.WithField(logfields.Path, path)

	os.Remove(path)
	server, err := net.Listen("unix", path)
	if err != nil {
		scopedLog.WithError(err).Fatal("Cannot listen on socket")
	}

	if os.Getuid() == 0 {
		err := api.SetDefaultPermissions(path)
		if err != nil {
			scopedLog.WithError(err).Fatal("Cannot set default permissions on socket")
		}
	}

	return server
}

func runNodeMonitor() {
	bpf.SetMapRoot(bpfRoot)

	eventSockPath := path.Join(defaults.RuntimePath, defaults.EventsPipe)
	pipe, err := os.OpenFile(eventSockPath, os.O_RDONLY, 0600)
	if err != nil {
		log.WithError(err).Fatalf("Unable to open named pipe %s for reading", eventSockPath)
	}
	defer pipe.Close() // stop receiving agent events

	// Open socket for using gops to get stacktraces of the agent.
	if err := gops.Listen(gops.Options{}); err != nil {
		log.WithError(err).Fatal("Unable to start gops")
	}

	common.RequireRootPrivilege(targetName)

	server1_0 := buildServerOrExit(defaults.MonitorSockPath1_0)
	defer server1_0.Close() // Stop accepting new v1.0 connections
	log.Infof("Serving cilium node monitor v1.0 API at unix://%s", defaults.MonitorSockPath1_0)

	server1_2 := buildServerOrExit(defaults.MonitorSockPath1_2)
	defer server1_2.Close() // Stop accepting new v1.2 connections
	log.Infof("Serving cilium node monitor v1.2 API at unix://%s", defaults.MonitorSockPath1_2)

	mainCtx, mainCtxCancel := context.WithCancel(context.Background())

	monitorSingleton, err = NewMonitor(mainCtx, npages, pipe, server1_0, server1_2)
	if err != nil {
		log.WithError(err).Fatal("Error initialising monitor handlers")
	}

	shutdownChan := make(chan os.Signal)
	signal.Notify(shutdownChan, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGTERM, syscall.SIGINT)
	sig := <-shutdownChan
	log.WithField(logfields.Signal, sig).Info("Exiting due to signal")
	mainCtxCancel() // Signal a shutdown to spawned goroutines
}
