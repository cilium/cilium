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
	"net"
	"net/http"
	_ "net/http/pprof" // a comment justifying it
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/hubble/api/v1/observer"
	"github.com/cilium/hubble/pkg/api"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/hubble/pkg/cilium/client"
	"github.com/cilium/hubble/pkg/fqdncache"
	"github.com/cilium/hubble/pkg/ipcache"
	"github.com/cilium/hubble/pkg/metrics"
	"github.com/cilium/hubble/pkg/parser"
	"github.com/cilium/hubble/pkg/server"
	"github.com/cilium/hubble/pkg/server/serveroption"
	"github.com/cilium/hubble/pkg/servicecache"
	"github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
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
			if err = Serve(ctx, log, listenClientUrls, s.GetGRPCServer()); err != nil {
				return err
			}
			if err := s.HandleMonitorSocket(ctx, nodeName); err != nil {
				return fmt.Errorf("failed to handle monitor socket: %v", err)
			}
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

var (
	maxFlows       uint32
	eventQueueSize uint32

	nodeName string

	listenClientUrls []string

	enabledMetrics []string
	metricsServer  string

	gopsVar, pprofVar bool
)

const (
	serverSocketPath = "unix:///var/run/hubble.sock"
	envNodeName      = "HUBBLE_NODE_NAME"
)

func validateArgs(log *logrus.Entry) error {
	if metricsServer != "" {
		if err := metrics.EnableMetrics(log, metricsServer, enabledMetrics); err != nil {
			return err
		}
	}
	return nil
}

func setupListeners(listenClientUrls []string) (listeners map[string]net.Listener, err error) {
	listeners = map[string]net.Listener{}
	defer func() {
		if err != nil {
			for _, list := range listeners {
				list.Close()
			}
		}
	}()

	for _, listenClientURL := range listenClientUrls {
		if listenClientURL == "" {
			continue
		}
		if !strings.HasPrefix(listenClientURL, "unix://") {
			var socket net.Listener
			socket, err = net.Listen("tcp", listenClientURL)
			if err != nil {
				return nil, err
			}
			listeners[listenClientURL] = socket
		} else {
			socketPath := strings.TrimPrefix(listenClientURL, "unix://")
			syscall.Unlink(socketPath)
			var socket net.Listener
			socket, err = net.Listen("unix", socketPath)
			if err != nil {
				return
			}

			if os.Getuid() == 0 {
				err = api.SetDefaultPermissions(socketPath)
				if err != nil {
					return nil, err
				}
			}
			listeners[listenClientURL] = socket
		}
	}
	return listeners, nil
}

// Serve starts the GRPC server on the provided socketPath. If the port is non-zero, it listens
// to the TCP port instead of the unix domain socket.
func Serve(ctx context.Context, log *logrus.Entry, listenClientUrls []string, s server.GRPCServer) error {
	clientListeners, err := setupListeners(listenClientUrls)
	if err != nil {
		return err
	}

	healthSrv := health.NewServer()
	healthSrv.SetServingStatus(v1.ObserverServiceName, healthpb.HealthCheckResponse_SERVING)

	clientGRPC := grpc.NewServer()

	observer.RegisterObserverServer(clientGRPC, s)
	healthpb.RegisterHealthServer(clientGRPC, healthSrv)

	for clientListURL, clientList := range clientListeners {
		go func(clientListURL string, clientList net.Listener) {
			log.WithField("client-listener", clientListURL).Info("Starting gRPC server on client-listener")
			err = clientGRPC.Serve(clientList)
			if err != nil {
				log.WithError(err).Error("failed to close grpc server")
			}
		}(clientListURL, clientList)
	}
	go func() {
		<-ctx.Done()
		clientGRPC.Stop()
	}()

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
