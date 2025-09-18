// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cell

import (
	"fmt"

	"github.com/spf13/pflag"
)

type config struct {
	// SkipUnknownCGroupIDs specifies if events with unknown cgroup ids should
	// be skipped.
	SkipUnknownCGroupIDs bool `mapstructure:"hubble-skip-unknown-cgroup-ids"`

	// EnableNetworkPolicyCorrelation controls whether to enable network policy correlation of Hubble flows
	EnableNetworkPolicyCorrelation bool `mapstructure:"hubble-network-policy-correlation-enabled"`

	// EnableRedact controls if sensitive information will be redacted from L7
	// flows.
	EnableRedact bool `mapstructure:"hubble-redact-enabled"`
	// RedactHttpURLQuery controls if the URL query will be redacted from flows.
	RedactHttpURLQuery bool `mapstructure:"hubble-redact-http-urlquery"`
	// RedactHttpUserInfo controls if the user info will be redacted from flows.
	RedactHttpUserInfo bool `mapstructure:"hubble-redact-http-userinfo"`
	// RedactHttpHeadersAllow controls which http headers will not be redacted
	// from flows.
	RedactHttpHeadersAllow []string `mapstructure:"hubble-redact-http-headers-allow"`
	// RedactHttpHeadersDeny controls which http headers will be redacted from
	// flows.
	RedactHttpHeadersDeny []string `mapstructure:"hubble-redact-http-headers-deny"`
	// RedactKafkaAPIKey controls if Kafka API key will be redacted from flows.
	RedactKafkaAPIKey bool `mapstructure:"hubble-redact-kafka-apikey"`
}

var defaultConfig = config{
	SkipUnknownCGroupIDs:           true,
	EnableNetworkPolicyCorrelation: true,
	EnableRedact:                   false,
	RedactHttpURLQuery:             false,
	RedactHttpUserInfo:             true,
	RedactHttpHeadersAllow:         []string{},
	RedactHttpHeadersDeny:          []string{},
	RedactKafkaAPIKey:              false,
}

func (cfg config) validate() error {
	if len(cfg.RedactHttpHeadersAllow) > 0 && len(cfg.RedactHttpHeadersDeny) > 0 {
		return fmt.Errorf("Only one of --hubble-redact-http-headers-allow and --hubble-redact-http-headers-deny can be specified, not both")
	}
	return nil
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-skip-unknown-cgroup-ids", def.SkipUnknownCGroupIDs, "Skip Hubble events with unknown cgroup ids")
	// Hubble field redaction configuration
	flags.Bool("hubble-redact-enabled", def.EnableRedact, "Hubble redact sensitive information from flows")
	flags.Bool("hubble-redact-http-urlquery", def.RedactHttpURLQuery, "Hubble redact http URL query from flows")
	flags.Bool("hubble-redact-http-userinfo", def.RedactHttpUserInfo, "Hubble redact http user info from flows")
	flags.StringSlice("hubble-redact-http-headers-allow", def.RedactHttpHeadersAllow, "HTTP headers to keep visible in flows")
	flags.StringSlice("hubble-redact-http-headers-deny", def.RedactHttpHeadersDeny, "HTTP headers to redact from flows")
	flags.Bool("hubble-redact-kafka-apikey", def.RedactKafkaAPIKey, "Hubble redact Kafka API key from flows")
	flags.Bool("hubble-network-policy-correlation-enabled", def.EnableNetworkPolicyCorrelation, "Enable network policy correlation of Hubble flows")
}
