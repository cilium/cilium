// Copyright 2017-2020 Authors of Hubble
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
	"net/http"
	_ "net/http/pprof" // a comment justifying it
	"os"
	"os/signal"

	"github.com/cilium/cilium/pkg/hubble/api"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/cilium"
	"github.com/cilium/cilium/pkg/hubble/cilium/client"
	"github.com/cilium/cilium/pkg/hubble/fqdncache"
	"github.com/cilium/cilium/pkg/hubble/ipcache"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/hubble/servicecache"

	"github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	serverSocketPath = "unix:///var/run/hubble.sock"
	envNodeName      = "HUBBLE_NODE_NAME"
)

var (
	maxFlows       uint32
	eventQueueSize uint32

	nodeName string

	listenClientUrls []string

	enabledMetrics []string
	metricsServer  string

	gopsVar, pprofVar bool
)

// New ...
func New(log *logrus.Entry) *cobra.Command {
	serverCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start gRPC server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateArgs(log); err != nil {
				return fmt.Errorf("failed to parse arguments: %v", err)
			}

			if gopsVar {
				log.Debug("starting gops agent")
				if err := agent.Listen(agent.Options{}); err != nil {
					return fmt.Errorf("failed to start gops agent: %v", err)
				}
			}

			if pprofVar {
				log.Debug("starting http/pprof handler")
				// Even though gops agent might also be running running, http
				// pprof has no overhead unless called upon and can be very
				// useful.
				go func() {
					// ignore http/pprof error
					_ = http.ListenAndServe(":6060", nil)
				}()
			}

			ciliumClient, err := client.NewClient()
			if err != nil {
				return fmt.Errorf("failed to get Cilium client: %v", err)
			}
			ipCache := ipcache.New()
			fqdnCache := fqdncache.New()
			serviceCache := servicecache.New()
			endpoints := v1.NewEndpoints()
			podGetter := &cilium.LegacyPodGetter{
				PodGetter:      ipCache,
				EndpointGetter: endpoints,
			}
			payloadParser, err := parser.New(endpoints, ciliumClient, fqdnCache, podGetter, serviceCache)
			if err != nil {
				return fmt.Errorf("failed to get parser: %v", err)
			}
			s, err := server.NewServer(
				ciliumClient,
				endpoints,
				ipCache,
				fqdnCache,
				serviceCache,
				payloadParser,
				int(maxFlows),
				int(eventQueueSize),
				log,
			)
			if err != nil {
				return fmt.Errorf("failed to initialize server: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			setupSigHandler(ctx, cancel)
			s.Start()
			srv, err := NewServer(log,
				WithListeners(listenClientUrls, api.GetGroupName()),
				WithHealthService(),
				WithObserverService(s.GetGRPCServer()),
			)
			if err != nil {
				return err
			}
			if err = srv.Serve(); err != nil {
				return err
			}
			if err := s.HandleMonitorSocket(ctx, nodeName); err != nil {
				return fmt.Errorf("failed to handle monitor socket: %v", err)
			}
			<-ctx.Done()
			srv.Stop()
			return nil
		},
	}

	serverCmd.Flags().StringArrayVarP(&listenClientUrls, "listen-client-urls", "", []string{serverSocketPath}, "List of URLs to listen on for client traffic.")
	serverCmd.Flags().Uint32Var(&maxFlows,
		"max-flows", uint32(serveroption.Default.MaxFlows),
		"Max number of flows to store in memory (gets rounded up to closest (2^n)-1",
	)
	serverCmd.Flags().Uint32Var(&eventQueueSize,
		"event-queue-size", uint32(serveroption.Default.MonitorBuffer),
		"Size of the event queue for received monitor events",
	)

	serverCmd.Flags().StringVar(&nodeName, "node-name", os.Getenv(envNodeName), "Node name where hubble is running (defaults to value set in env variable '"+envNodeName+"'")

	serverCmd.Flags().StringSliceVar(&enabledMetrics, "metric", []string{}, "Enable metrics reporting")
	serverCmd.Flags().StringVar(&metricsServer, "metrics-server", "", "Address to serve metrics on")

	serverCmd.Flags().BoolVar(&gopsVar, "gops", true, "Run gops agent")
	serverCmd.Flags().BoolVar(&pprofVar, "pprof", false, "Run http/pprof handler")
	serverCmd.Flags().Lookup("gops").Hidden = true
	serverCmd.Flags().Lookup("pprof").Hidden = true

	return serverCmd
}

func validateArgs(log *logrus.Entry) error {
	if metricsServer != "" {
		if err := metrics.EnableMetrics(log, metricsServer, enabledMetrics); err != nil {
			return err
		}
	}
	return nil
}

func setupSigHandler(ctx context.Context, cancel context.CancelFunc) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		select {
		case <-ctx.Done():
		case <-signalChan:
			fmt.Printf("\nReceived an interrupt, disconnecting from monitor...\n\n")
			cancel()
		}
	}()
}
