// Copyright 2016-2017 Authors of Cilium
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

package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// the global Envoy instance
var envoyProxy *envoy.Envoy

// EnvoyRedirect implements the Redirect interface for a l7 proxy
type EnvoyRedirect struct {
	id      string
	toPort  uint16
	ingress bool
	source  ProxySource
}

// ToPort returns the redirect port of an EnvoyRedirect
func (r *EnvoyRedirect) ToPort() uint16 {
	return r.toPort
}

// IsIngress returns true if the redirect is for ingress, and false for egress.
func (r *EnvoyRedirect) IsIngress() bool {
	return r.ingress
}

func (r *EnvoyRedirect) getSource() ProxySource {
	return r.source
}

var envoyOnce sync.Once

// createEnvoyRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createEnvoyRedirect(l4 *policy.L4Filter, id string, source ProxySource, to uint16) (Redirect, error) {
	envoyOnce.Do(func() {
		// Start Envoy on first invocation
		envoyProxy = envoy.StartEnvoy(true, 0, viper.GetString("state-dir"),
			viper.GetString("state-dir"), 0)
	})

	if envoyProxy != nil {
		redir := &EnvoyRedirect{
			id:      id,
			toPort:  to,
			ingress: l4.Ingress,
			source:  source,
		}

		envoyProxy.AddListener(id, to, l4.L7RulesPerEp, l4.Ingress, redir)

		return redir, nil
	}

	return nil, fmt.Errorf("%s: Envoy proxy process failed to start, can not add redirect ", id)
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (r *EnvoyRedirect) UpdateRules(l4 *policy.L4Filter) error {
	if envoyProxy != nil {
		envoyProxy.UpdateListener(r.id, l4.L7RulesPerEp)
		return nil
	}
	return fmt.Errorf("%s: Envoy proxy process failed to start, can not update redirect ", r.id)
}

// Close the redirect.
func (r *EnvoyRedirect) Close() {
	if envoyProxy != nil {
		envoyProxy.RemoveListener(r.id)
	}
}

// Log does access logging for Envoy
func (r *EnvoyRedirect) Log(pblog *envoy.HttpLogEntry) {
	log.Infof("%s: Access log message: %s", pblog.CiliumResourceName, pblog.String())

	headers := make(http.Header)
	for _, header := range pblog.Headers {
		headers.Add(header.Key, header.Value)
	}

	URL := url.URL{
		Scheme: pblog.Scheme,
		Host:   pblog.Host,
		Path:   pblog.Path,
	}

	var proto string
	switch pblog.HttpProtocol {
	case envoy.Protocol_HTTP10:
		proto = "HTTP/1"
	case envoy.Protocol_HTTP11:
		proto = "HTTP/1.1"
	case envoy.Protocol_HTTP2:
		proto = "HTTP/2"
	}

	record := newHTTPLogRecord(r, pblog.Method, &URL, proto, headers)

	record.fillInfo(r, pblog.SourceAddress, pblog.DestinationAddress, pblog.SourceSecurityId)

	var flowType accesslog.FlowType
	var verdict accesslog.FlowVerdict

	switch pblog.EntryType {
	case envoy.EntryType_Denied:
		flowType, verdict = accesslog.TypeRequest, accesslog.VerdictDenied
	case envoy.EntryType_Request:
		flowType, verdict = accesslog.TypeRequest, accesslog.VerdictForwarded
	case envoy.EntryType_Response:
		flowType, verdict = accesslog.TypeResponse, accesslog.VerdictForwarded
	}

	record.Timestamp = time.Unix(int64(pblog.Timestamp/1000000000), int64(pblog.Timestamp%1000000000)).UTC().Format(time.RFC3339Nano)
	record.logStamped(flowType, verdict, int(pblog.Status), pblog.CiliumRuleRef)
}
