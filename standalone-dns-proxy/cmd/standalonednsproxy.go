// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"iter"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
	sdpmetrics "github.com/cilium/cilium/standalone-dns-proxy/pkg/metrics"
)

// ReadinessStatusProvider is an interface for checking the readiness status
type ReadinessStatusProvider interface {
	IsReady() bool
}

type StandaloneDNSProxy struct {
	logger *slog.Logger

	standaloneDNSProxyServerPort uint16
	enableL7Proxy                bool
	enableStandaloneDNSProxy     bool
	proxyPort                    uint16

	// connHandler is the gRPC connection handler client for standalone DNS proxy
	connHandler client.ConnectionHandler

	// dnsProxierAllowedRuleKeys is the cache of allowed DNS rule keys(endpointID + portproto)
	// in DNS proxier managed by SDP.
	// This cache is required to clean up stale allowed DNS rules in proxier for keys that
	// were removed in the snapshot update received from the agent.
	dnsProxierAllowedRules map[dnsRuleKey]struct{}
	dnsProxier             proxy.DNSProxier

	// dnsRulesTable is the table that holds DNS rules received from the Cilium agent
	// It is used by the DNS proxy to enforce DNS policies
	dnsRulesTable statedb.RWTable[client.DNSRules]
	db            *statedb.DB
	jobGroup      job.Group

	// metrics tracks errors for the standalone DNS proxy
	metrics *sdpmetrics.Metrics

	// readinessStatus tracks the readiness status of this standalone DNS proxy instance
	readinessStatus atomic.Bool
}

// dnsRuleKey uniquely identifies one (endpointID, portProto) entry in the
// DNS proxy's allowed map.
type dnsRuleKey struct {
	endpointID uint64
	portProto  restore.PortProto
}

// IsReady returns the current readiness status of the standalone DNS proxy
func (sdp *StandaloneDNSProxy) IsReady() bool {
	return sdp.readinessStatus.Load()
}

// setReady sets the readiness status of the standalone DNS proxy
func (sdp *StandaloneDNSProxy) setReady(ready bool) {
	sdp.readinessStatus.Store(ready)
}

// NewStandaloneDNSProxy creates a new StandaloneDNSProxy instance
func NewStandaloneDNSProxy(params standaloneDNSProxyParams) *StandaloneDNSProxy {
	return &StandaloneDNSProxy{
		logger:                       params.Logger,
		enableL7Proxy:                params.AgentConfig.EnableL7Proxy,
		enableStandaloneDNSProxy:     params.FQDNConfig.EnableStandaloneDNSProxy,
		standaloneDNSProxyServerPort: uint16(params.FQDNConfig.StandaloneDNSProxyServerPort),
		proxyPort:                    uint16(params.AgentConfig.ToFQDNsProxyPort),
		connHandler:                  params.ConnectionHandler,
		dnsProxier:                   params.DNSProxier,
		db:                           params.DB,
		dnsRulesTable:                params.DNSRulesTable,
		jobGroup:                     params.JobGroup,
		metrics:                      params.Metrics,
	}
}

// NewReadinessStatusProvider creates a ReadinessStatusProvider from the StandaloneDNSProxy
func NewReadinessStatusProvider(sdp *StandaloneDNSProxy) ReadinessStatusProvider {
	return sdp
}

// StartStandaloneDNSProxy starts the connection management and waits for connection before starting DNS proxy
// It also sets up the DNS rules table watcher to update the DNS proxy with the latest rules received from the Cilium agent
func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy() error {
	sdp.logger.Info("Starting standalone DNS proxy")

	// watch the connection state and start the DNS proxy once connected
	sdp.jobGroup.Add(job.OneShot("sdp-connection-watcher", sdp.WatchConnection, job.WithShutdown()))

	sdp.jobGroup.Add(job.OneShot("sdp-watch-dns-rules", sdp.WatchDNSRulesTable,
		job.WithRetry(3, &job.ExponentialBackoff{Min: 5 * time.Second, Max: 10 * time.Second}),
		job.WithShutdown()))

	sdp.logger.Info("Standalone DNS proxy started")

	// Mark the proxy as ready since it has started successfully
	sdp.setReady(true)

	return nil
}

// watchConnection watches the connection state
func (sdp *StandaloneDNSProxy) WatchConnection(ctx context.Context, _ cell.Health) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			sdp.logger.Info("Stopping connection watcher")
			return nil
		case <-ticker.C:
			if sdp.connHandler.IsConnected() {
				sdp.logger.Info("Connection to Cilium agent established")
				// Start the DNS proxy once the connection is established
				if err := sdp.dnsProxier.Listen(sdp.proxyPort); err != nil {
					sdp.logger.Error("Failed to start DNS proxy", logfields.Error, err)
					sdp.metrics.ProxyBootstrapError.Inc()
					return err
				}
				return nil
			}
		}
	}
}

// WatchDNSRulesTable watches the DNS rules table for changes and updates the DNS proxy accordingly
func (sdp *StandaloneDNSProxy) WatchDNSRulesTable(ctx context.Context, _ cell.Health) error {
	limiter := rate.NewLimiter(100*time.Millisecond, 1)
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
			rules, newWatch := sdp.dnsRulesTable.AllWatch(sdp.db.ReadTxn())
			// Update the DNS proxy with the latest rules
			if err := sdp.updateDNSRules(rules); err != nil {
				sdp.logger.Error("Failed to update DNS rules", logfields.Error, err)
			}
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

	// Mark as unhealthy since we're shutting down
	sdp.setReady(false)

	// Stop DNS proxy first
	sdp.dnsProxier.Cleanup()

	// Stop all controllers
	sdp.connHandler.StopConnection()

	sdp.logger.Info("Standalone DNS proxy stopped")
	return nil
}

func (sdp *StandaloneDNSProxy) updateDNSRules(dnsRules iter.Seq2[client.DNSRules, statedb.Revision]) (retErr error) {
	var revertFuncs revert.RevertStack
	defer func() {
		if retErr != nil {
			sdp.logger.Error("Failed to update DNS rules, reverting changes", logfields.Error, retErr)
			if rErr := revertFuncs.Revert(); rErr != nil {
				sdp.logger.Error("Failed to revert DNS rules changes", logfields.Error, rErr)
			}
		}
	}()

	dnsProxierAllowedKeys := make(map[dnsRuleKey]struct{})
	for rule := range dnsRules {
		key := dnsRuleKey{endpointID: uint64(rule.EndpointID), portProto: rule.PortProto}
		dnsProxierAllowedKeys[key] = struct{}{}

		revertFunc, err := sdp.dnsProxier.UpdateAllowed(uint64(rule.EndpointID), rule.PortProto, rule.DNSRule)
		if err != nil {
			retErr = err
			return
		}
		revertFuncs.Push(revertFunc)
	}

	for prevRule := range sdp.dnsProxierAllowedRules {
		if _, ok := dnsProxierAllowedKeys[prevRule]; !ok {
			// Remove entries that were present in the previous snapshot but are
			// absent from the current one. Passing nil rules causes the proxy to
			// delete the allowed entry and release regex-cache references.
			if _, err := sdp.dnsProxier.UpdateAllowed(prevRule.endpointID, prevRule.portProto, nil); err != nil {
				sdp.logger.Warn("Failed to remove stale DNS rule",
					logfields.Error, err,
					logfields.EndpointID, prevRule.endpointID,
					logfields.PortProtocol, prevRule.portProto)
			}
		}
	}

	sdp.dnsProxierAllowedRules = dnsProxierAllowedKeys
	return nil
}
