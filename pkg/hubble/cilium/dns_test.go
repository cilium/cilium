// Copyright 2019 Authors of Hubble
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

// +build !privileged_tests

package cilium

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hubble/logger"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	monitorAPI "github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/stretchr/testify/assert"
)

func TestObserverServer_consumeLogRecordNotifyChannel(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	lr := monitorAPI.LogRecordNotify{
		LogRecord: accesslog.LogRecord{
			Type:             accesslog.TypeResponse,
			Timestamp:        "2006-01-02T15:04:05.999999999Z",
			ObservationPoint: accesslog.Ingress,
			SourceEndpoint: accesslog.EndpointInfo{
				ID:           123,
				IPv4:         "",
				IPv6:         "",
				Port:         0,
				Identity:     0,
				Labels:       nil,
				LabelsSHA256: "",
			},
			IPVersion:         accesslog.VersionIPV6,
			Verdict:           accesslog.VerdictForwarded,
			TransportProtocol: accesslog.TransportProtocol(u8proto.UDP),
			ServiceInfo:       nil,
			DropReason:        nil,
			DNS: &accesslog.LogRecordDNS{
				Query:             "deathstar.empire.svc.cluster.local.",
				IPs:               []net.IP{net.ParseIP("1.2.3.4")},
				TTL:               5,
				ObservationSource: accesslog.DNSSourceProxy,
				RCode:             0,
				QTypes:            []uint16{1},
			},
		},
	}
	fakeFQDNCache := &testutils.FakeFQDNCache{
		OnAddDNSLookup: func(epID uint64, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32) {
			defer wg.Done()
			assert.Equal(t, uint64(123), epID)
			assert.Equal(t, []net.IP{net.ParseIP("1.2.3.4")}, ips)
			assert.Equal(t, "deathstar.empire.svc.cluster.local.", domainName)
		},
	}

	c := &State{
		fqdnCache: fakeFQDNCache,
		logRecord: make(chan monitorAPI.LogRecordNotify, 1),
		log:       logger.GetLogger(),
	}
	go c.consumeLogRecordNotifyChannel()

	c.GetLogRecordNotifyChannel() <- lr
	wg.Wait()
}
