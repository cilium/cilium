// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package options

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/logging"
)

func TestRedact(t *testing.T) {
	want := "level=info msg=\"configured Hubble with redact options\" options=\"&{CacheSize:3 HubbleRedactSettings:{Enabled:true RedactHTTPQuery:false RedactHTTPUserInfo:false RedactKafkaAPIKey:false RedactHttpHeaders:{Allow:map[] Deny:map[]}} EnableNetworkPolicyEnrichment:false}\"\n"
	var buf bytes.Buffer
	logger := slog.New(
		slog.NewTextHandler(&buf,
			&slog.HandlerOptions{
				ReplaceAttr: logging.ReplaceAttrFnWithoutTimestamp,
			},
		),
	)
	opt := Redact(logger, false, false, false, nil, nil)
	opt(&Options{
		CacheSize: 3,
		HubbleRedactSettings: HubbleRedactSettings{
			Enabled:            false,
			RedactHTTPQuery:    false,
			RedactHTTPUserInfo: false,
			RedactKafkaAPIKey:  false,
			RedactHttpHeaders: HttpHeadersList{
				Allow: map[string]struct{}{},
				Deny:  map[string]struct{}{"tracecontent": {}},
			},
		},
	})
	assert.Equal(t, want, buf.String())
}

func TestEnableNetworkPolicyEnrichment(t *testing.T) {
	want := "level=info msg=\"configured Hubble with network policy enrichment options\" options=\"&{CacheSize:0 HubbleRedactSettings:{Enabled:false RedactHTTPQuery:false RedactHTTPUserInfo:false RedactKafkaAPIKey:false RedactHttpHeaders:{Allow:map[] Deny:map[]}} EnableNetworkPolicyEnrichment:true}\"\n"
	var buf bytes.Buffer
	logger := slog.New(
		slog.NewTextHandler(&buf,
			&slog.HandlerOptions{
				ReplaceAttr: logging.ReplaceAttrFnWithoutTimestamp,
			},
		),
	)
	opt := WithNetworkPolicyEnrichment(logger, true)
	opt(&Options{
		EnableNetworkPolicyEnrichment: true,
	})
	assert.Equal(t, want, buf.String())
}
