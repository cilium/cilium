// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
)

type StandaloneDNSProxy struct {
	logger *slog.Logger

	standaloneDNSProxyServerPort uint16
	enableL7Proxy                bool
	enableStandaloneDNSProxy     bool
	dnsProxier                   proxy.DNSProxier

	// connHandler is the gRPC connection handler client for standalone DNS proxy
	connHandler client.ConnectionHandler

	// dnsRulesTable is the table that holds DNS rules received from the Cilium agent
	// It is used by the DNS proxy to enforce DNS policies
	dnsRulesTable statedb.RWTable[service.PolicyRules]
	db            *statedb.DB
	jobGroup      job.Group
}

// NewStandaloneDNSProxy creates a new StandaloneDNSProxy instance
func NewStandaloneDNSProxy(params standaloneDNSProxyParams) *StandaloneDNSProxy {
	return &StandaloneDNSProxy{
		logger:                       params.Logger,
		enableL7Proxy:                params.AgentConfig.EnableL7Proxy,
		enableStandaloneDNSProxy:     params.FQDNConfig.EnableStandaloneDNSProxy,
		standaloneDNSProxyServerPort: uint16(params.FQDNConfig.StandaloneDNSProxyServerPort),
		connHandler:                  params.ConnectionHandler,
		dnsProxier:                   params.DNSProxier,
		db:                           params.DB,
		dnsRulesTable:                params.DNSRulesTable,
		jobGroup:                     params.JobGroup,
	}
}

// StartStandaloneDNSProxy starts the connection management and waits for connection before starting DNS proxy
// It also sets up the DNS rules table watcher to update the DNS proxy with the latest rules received from the Cilium agent
func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy() error {
	sdp.logger.Info("Starting standalone DNS proxy")

	// start the connection handler
	sdp.connHandler.StartConnection()

	// Wait for the connection to be established and start the proxy, will be added in future PRs
	// Note: This is a placeholder for the actual implementation.
	// if err := sdp.dnsProxier.Listen(sdp.proxyPort); err != nil {
	// 	return fmt.Errorf("error opening dns proxy socket(s): %w", err)
	// }

	sdp.jobGroup.Add(job.OneShot("sdp-watch-dns-rules", sdp.WatchDNSRulesTable,
		job.WithRetry(3, &job.ExponentialBackoff{Min: 5 * time.Second, Max: 10 * time.Second}),
		job.WithShutdown()))

	sdp.logger.Info("Standalone DNS proxy started")
	return nil
}

// WatchDNSRulesTable watches the DNS rules table for changes and updates the DNS proxy accordingly
func (sdp *StandaloneDNSProxy) WatchDNSRulesTable(ctx context.Context, _ cell.Health) error {
	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()

	rulesWatch := func() <-chan struct{} {
		ch := make(chan struct{})
		close(ch)
		return ch
	}()

	for {
		select {
		case <-ctx.Done():
			sdp.logger.Info("Stopping DNS rules table watcher")
			return nil
		case <-rulesWatch:
			_, newWatch := sdp.dnsRulesTable.AllWatch(sdp.db.ReadTxn())
			// Update the DNS proxy with the latest rules
			rulesWatch = newWatch
		}

		// Limit the rate at which we send the full snapshots
		if err := limiter.Wait(ctx); err != nil {
			sdp.logger.Error("Failed to wait for rate limiter", logfields.Error, err)
			return err
		}
	}
}

// StopStandaloneDNSProxy stops the standalone DNS proxy and cleanup resources
func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	sdp.logger.Info("Stopping standalone DNS proxy")

	// Stop DNS proxy first
	sdp.dnsProxier.Cleanup()

	// Stop all controllers
	sdp.connHandler.StopConnection()

	sdp.logger.Info("Standalone DNS proxy stopped")
	return nil
}
