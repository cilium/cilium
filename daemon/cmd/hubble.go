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

package cmd

import (
	"strings"

	hubbleServe "github.com/cilium/cilium/daemon/cmd/hubble-serve"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/hubble/listener"
	hubbleMetrics "github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/parser"
	hubbleServer "github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

func (d *Daemon) launchHubble() {
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble")
	if !option.Config.EnableHubble {
		logger.Info("Hubble server is disabled")
		return
	}
	addresses := append(option.Config.HubbleListenAddresses, "unix://"+option.Config.HubbleSocketPath)
	for _, address := range addresses {
		// TODO: remove warning once mutual TLS has been implemented
		if !strings.HasPrefix(address, "unix://") {
			logger.WithField("address", address).Warn("Hubble server will be exposing its API insecurely on this address")
		}
	}
	payloadParser, err := parser.New(d, d, d, ipcache.IPIdentityCache, d)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble")
		return
	}
	observerServer, err := hubbleServer.NewLocalServer(payloadParser, logger,
		serveroption.WithMaxFlows(option.Config.HubbleFlowBufferSize),
		serveroption.WithMonitorBuffer(option.Config.HubbleEventQueueSize),
		serveroption.WithCiliumDaemon(d))
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble")
		return
	}
	go observerServer.Start()
	d.monitorAgent.GetMonitor().RegisterNewListener(d.ctx, listener.NewHubbleListener(observerServer))

	srv, err := hubbleServe.NewServer(logger,
		hubbleServe.WithListeners(addresses, api.CiliumGroupName),
		hubbleServe.WithHealthService(),
		hubbleServe.WithObserverService(observerServer),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble server")
		return
	}
	logger.WithField("addresses", addresses).Info("Starting Hubble server")
	if err := srv.Serve(); err != nil {
		logger.WithError(err).Error("Failed to start Hubble server")
		return
	}
	go func() {
		<-d.ctx.Done()
		srv.Stop()
	}()

	if option.Config.HubbleMetricsServer != "" {
		logger.WithFields(logrus.Fields{
			"address": option.Config.HubbleMetricsServer,
			"metrics": option.Config.HubbleMetrics,
		}).Info("Starting Hubble Metrics server")
		if err := hubbleMetrics.EnableMetrics(log, option.Config.HubbleMetricsServer, option.Config.HubbleMetrics); err != nil {
			logger.WithError(err).Warn("Failed to initialize Hubble metrics server")
			return
		}
	}
}
