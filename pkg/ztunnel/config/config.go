// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var DefaultConfig = Config{
	EnableZTunnel:                  false,
	EndpointEventChannelBufferSize: 1,
}

// Config is a shared config for all ZTunnel module's cells.
// Note: The operator reads EnableZTunnel directly from the ConfigMap,
// while the agent uses this Config struct for dependency injection.
type Config struct {
	EnableZTunnel                  bool
	EndpointEventChannelBufferSize int    `mapstructure:"ztunnel-endpoint-event-channel-buffer-size"`
	SpiffeTrustDomain              string `mapstructure:"ztunnel-spiffe-trust-domain"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
	flags.Int("ztunnel-endpoint-event-channel-buffer-size", 1, "Buffer size for the ztunnel endpoint event channel")
	flags.MarkHidden("ztunnel-endpoint-event-channel-buffer-size")
	flags.String("ztunnel-spiffe-trust-domain", c.SpiffeTrustDomain, "The SPIFFE trust domain for ztunnel workload identities. Empty uses ztunnel's default trust domain.")
}

func (c Config) Validate() error {
	if c.EndpointEventChannelBufferSize < 0 {
		return fmt.Errorf("ztunnel-endpoint-event-channel-buffer-size must be non-negative, got %d", c.EndpointEventChannelBufferSize)
	}
	if c.SpiffeTrustDomain != "" {
		domain, err := spiffeid.TrustDomainFromString(c.SpiffeTrustDomain)
		if err != nil {
			return fmt.Errorf("invalid ztunnel SPIFFE trust domain: %w", err)
		}
		if domain.Name() != c.SpiffeTrustDomain {
			return fmt.Errorf("invalid ztunnel SPIFFE trust domain: use a trust domain name, not a SPIFFE ID")
		}
	}
	return nil
}
