// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/option"
)

type StandaloneDNSProxy struct {
	logger *slog.Logger

	standaloneDNSProxyServerPort uint16
	enableL7Proxy                bool
	enableStandaloneDNSProxy     bool
}

// NewStandaloneDNSProxy creates a new standalone DNS proxy
func NewStandaloneDNSProxy(logger *slog.Logger, agentCfg *option.DaemonConfig, fqdnCfg service.FQDNConfig) *StandaloneDNSProxy {
	return &StandaloneDNSProxy{
		logger:                       logger,
		enableL7Proxy:                agentCfg.EnableL7Proxy,
		enableStandaloneDNSProxy:     fqdnCfg.EnableStandaloneDNSProxy,
		standaloneDNSProxyServerPort: uint16(fqdnCfg.StandaloneDNSProxyServerPort),
	}
}

// Note: This is intentionally left blank. The actual implementation will be added in a future commit.
func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	return nil
}

// Note: This is intentionally left blank. The actual implementation will be added in a future commit.
func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy() error {
	return nil
}
