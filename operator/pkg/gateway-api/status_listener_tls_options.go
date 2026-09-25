// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

var supportedTLSVersions = map[string]int{
	"1.2": 2,
	"1.3": 3,
}

func parseTLSOptions(l gatewayv1.Listener) (*model.TLSOptions, error) {
	if l.TLS == nil {
		return nil, nil
	}

	parsed := &model.TLSOptions{}
	for option, value := range l.TLS.Options {
		key := string(option)
		// Validate only 'cilium.io/' options, other should be ignored.
		if !strings.HasPrefix(key, "cilium.io/") {
			continue
		}

		if helpers.IsTLSPassthroughListener(&l) {
			return nil, fmt.Errorf("TLS option %s is not supported on TLS passthrough listeners", key)
		}

		switch key {
		case model.TLSOptionsMinVersion:
			parsed.MinVersion = string(value)
		case model.TLSOptionsMaxVersion:
			parsed.MaxVersion = string(value)
		default:
			return nil, fmt.Errorf("TLS Option %s is not supported", key)
		}

		if _, ok := supportedTLSVersions[string(value)]; !ok {
			return nil, fmt.Errorf("TLS Value %s is not supported in %s", value, key)
		}
	}

	min := model.TLSOptionsDefaultMinVersion
	if parsed.MinVersion != "" {
		min = parsed.MinVersion
	}

	max := model.TLSOptionsDefaultMaxVersion
	if parsed.MaxVersion != "" {
		max = parsed.MaxVersion
	}

	if supportedTLSVersions[min] > supportedTLSVersions[max] {
		return nil, fmt.Errorf("TLS minimum version %s must not exceed maximum version %s", min, max)
	}

	if parsed.MinVersion == "" && parsed.MaxVersion == "" {
		return nil, nil
	}

	return parsed, nil
}
