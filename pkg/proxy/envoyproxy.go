// Copyright 2016-2018 Authors of Cilium
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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// the global Envoy instance
var envoyProxy *envoy.Envoy

// envoyRedirect implements the Redirect interface for a l7 proxy
type envoyRedirect struct {
	redirect  *Redirect
	xdsServer *envoy.XDSServer
}

var envoyOnce sync.Once

// createEnvoyRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createEnvoyRedirect(r *Redirect, stateDir string, xdsServer *envoy.XDSServer, wg *completion.WaitGroup) (RedirectImplementation, error) {
	envoyOnce.Do(func() {
		// Start Envoy on first invocation
		envoyProxy = envoy.StartEnvoy(9901, stateDir, viper.GetString("envoy-log"), 0)
	})

	if envoyProxy != nil {
		redir := &envoyRedirect{
			redirect:  r,
			xdsServer: xdsServer,
		}

		ip := r.source.GetIPv4Address()
		if ip == "" {
			ip = r.source.GetIPv6Address()
		}
		if ip == "" {
			return nil, fmt.Errorf("%s: Cannot create redirect, proxy source has no IP address.", r.id)
		}
		xdsServer.AddListener(r.id, ip, r.ProxyPort, r.ingress, redir, wg)

		return redir, nil
	}

	return nil, fmt.Errorf("%s: Envoy proxy process failed to start, can not add redirect ", r.id)
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (r *envoyRedirect) UpdateRules(wg *completion.WaitGroup) error {
	return nil
}

// Close the redirect.
func (r *envoyRedirect) Close(wg *completion.WaitGroup) {
	if envoyProxy != nil {
		r.xdsServer.RemoveListener(r.redirect.id, wg)
	}
}

func parseURL(pblog *cilium.HttpLogEntry) *url.URL {
	path := strings.TrimPrefix(pblog.Path, "/")
	u, err := url.Parse(fmt.Sprintf("%s://%s/%s", pblog.Scheme, pblog.Host, path))
	if err != nil {
		u = &url.URL{
			Scheme: pblog.Scheme,
			Host:   pblog.Host,
			Path:   pblog.Path,
		}
	}

	return u
}

// Log is called by the envoy package to log an individual access log record
func (r *envoyRedirect) Log(pblog *cilium.HttpLogEntry) {
	flowdebug.Log(log.WithFields(logrus.Fields{}),
		fmt.Sprintf("%s: Access log message: %s", pblog.PolicyName, pblog.String()))

	record := logger.NewLogRecord(r.redirect, pblog.GetFlowType(),
		logger.LogTags.Timestamp(time.Unix(int64(pblog.Timestamp/1000000000), int64(pblog.Timestamp%1000000000))),
		logger.LogTags.Verdict(pblog.GetVerdict(), pblog.CiliumRuleRef),
		logger.LogTags.Addressing(logger.AddressingInfo{
			SrcIPPort:   pblog.SourceAddress,
			DstIPPort:   pblog.DestinationAddress,
			SrcIdentity: pblog.SourceSecurityId,
		}),
		logger.LogTags.HTTP(&accesslog.LogRecordHTTP{
			Method:   pblog.Method,
			Code:     int(pblog.Status),
			URL:      parseURL(pblog),
			Protocol: pblog.GetProtocol(),
			Headers:  pblog.GetNetHttpHeaders(),
		}))

	record.Log()
}
