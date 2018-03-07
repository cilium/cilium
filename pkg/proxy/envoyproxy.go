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

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// the global Envoy instance
var envoyProxy *envoy.Envoy

// envoyRedirect implements the Redirect interface for a l7 proxy
type envoyRedirect struct {
	redirect *Redirect
}

var envoyOnce sync.Once

// createEnvoyRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createEnvoyRedirect(r *Redirect, wg *completion.WaitGroup) (RedirectImplementation, error) {
	envoyOnce.Do(func() {
		// Start Envoy on first invocation
		envoyProxy = envoy.StartEnvoy(9901, viper.GetString("state-dir"),
			viper.GetString("envoy-log"), 0)
	})

	if envoyProxy != nil {
		redir := &envoyRedirect{redirect: r}

		envoyProxy.AddListener(r.id, r.ProxyPort, r.rules, r.ingress, redir, wg)

		return redir, nil
	}

	return nil, fmt.Errorf("%s: Envoy proxy process failed to start, can not add redirect ", r.id)
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (r *envoyRedirect) UpdateRules(wg *completion.WaitGroup) error {
	if envoyProxy != nil {
		envoyProxy.UpdateListener(r.redirect.id, r.redirect.rules, wg)
		return nil
	}
	return fmt.Errorf("%s: Envoy proxy process failed to start, can not update redirect ", r.redirect.id)
}

// Close the redirect.
func (r *envoyRedirect) Close(wg *completion.WaitGroup) {
	if envoyProxy != nil {
		envoyProxy.RemoveListener(r.redirect.id, wg)
	}
}

// Log does access logging for Envoy
func (r *envoyRedirect) Log(pblog *envoy.HttpLogEntry) {
	flowdebug.Log(log.WithFields(logrus.Fields{}),
		fmt.Sprintf("%s: Access log message: %s", pblog.CiliumResourceName, pblog.String()))

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

	record := newHTTPLogRecord(r.redirect, pblog.Method, &URL, proto, headers)

	record.fillInfo(r.redirect, pblog.SourceAddress, pblog.DestinationAddress, pblog.SourceSecurityId)

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
