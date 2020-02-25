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

package cilium

import (
	"net"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

const (
	fqdnCacheRetryInterval   = 1 * time.Second
	fqdnCacheRefreshInterval = 5 * time.Minute
)

// FqdnCache defines an interface for caching FQDN info from Cilium.
type FqdnCache interface {
	InitializeFrom(entries []*models.DNSLookup)
	AddDNSLookup(epID uint64, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32)
	GetNamesOf(epID uint64, ip net.IP) []string
}

// syncFQDNCache regularily syncs DNS lookups from Cilium into our local FQDN
// cache
func (s *State) syncFQDNCache() {
	for {
		entries, err := s.ciliumClient.GetFqdnCache()
		if err != nil {
			s.log.WithError(err).Error("Unable to obtain fqdn cache from cilium")
			time.Sleep(fqdnCacheRetryInterval)
			continue
		}

		s.fqdnCache.InitializeFrom(entries)
		s.log.WithField("entries", len(entries)).Debug("Fetched DNS cache from cilium")
		time.Sleep(fqdnCacheRefreshInterval)
	}
}

// consumeLogRecordNotifyChannel consume
func (s *State) consumeLogRecordNotifyChannel() {
	for logRecord := range s.logRecord {
		if logRecord.DNS == nil {
			continue
		}
		switch logRecord.LogRecord.Type {
		case accesslog.TypeResponse:
			epID := logRecord.SourceEndpoint.ID
			if epID == 0 {
				continue
			}
			domainName := logRecord.DNS.Query
			if domainName == "" {
				continue
			}
			ips := logRecord.DNS.IPs
			if ips == nil {
				continue
			}
			lookupTime, err := time.Parse(time.RFC3339Nano, logRecord.Timestamp)
			if err != nil {
				s.log.WithError(err).Warn("Unable to parse timestamp of DNS lookup")
				continue
			}
			s.fqdnCache.AddDNSLookup(epID, lookupTime, domainName, ips, logRecord.DNS.TTL)
		}
	}
}
