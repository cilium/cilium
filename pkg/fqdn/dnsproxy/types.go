// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

type IPCache interface {
	// LookupSecIDByIP is a provided callback that returns the IP's security ID
	// from the ipcache.
	LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool)

	// LookupByIdentity is a provided callback that returns the IPs of a given security ID.
	LookupByIdentity(nid identity.NumericIdentity) []string
}

// LookupEndpointIDByIPFunc is a provided callback that returns the endpoint ID
// as a uint16.
type LookupEndpointIDByIPFunc func(ip netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error)

// NotifyOnDNSMsgFunc handles propagating DNS response data
// See DNSProxy.LookupEndpointIDByIP for usage.
type NotifyOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *ProxyRequestContext) error

// ErrFailedAcquireSemaphore is an an error representing the DNS proxy's
// failure to acquire the semaphore. This is error is treated like a timeout.
type ErrFailedAcquireSemaphore struct {
	parallel int
}

func (e ErrFailedAcquireSemaphore) Timeout() bool { return true }

// Temporary is deprecated. Return false.
func (e ErrFailedAcquireSemaphore) Temporary() bool { return false }

func (e ErrFailedAcquireSemaphore) Error() string {
	return fmt.Sprintf(
		"failed to acquire DNS proxy semaphore, %d parallel requests already in-flight",
		e.parallel,
	)
}

// ErrTimedOutAcquireSemaphore is an an error representing the DNS proxy timing
// out when acquiring the semaphore. It is treated the same as
// ErrTimedOutAcquireSemaphore.
type ErrTimedOutAcquireSemaphore struct {
	ErrFailedAcquireSemaphore

	gracePeriod time.Duration
}

func (e ErrTimedOutAcquireSemaphore) Error() string {
	return fmt.Sprintf(
		"timed out after %v acquiring DNS proxy semaphore, %d parallel requests already in-flight",
		e.gracePeriod,
		e.parallel,
	)
}

// ErrDNSRequestNoEndpoint represents an error when the local daemon cannot
// find the corresponding endpoint that triggered a DNS request processed by
// the local DNS proxy (FQDN proxy).
type ErrDNSRequestNoEndpoint struct{}

func (ErrDNSRequestNoEndpoint) Error() string {
	return "DNS request cannot be associated with an existing endpoint"
}

// ProxyRequestContext proxy dns request context struct to send in the callback
type ProxyRequestContext struct {
	TotalTime      spanstat.SpanStat
	ProcessingTime spanstat.SpanStat // This is going to happen at the end of the second callback.
	// Error is a enum of [timeout, allow, denied, proxyerr].
	UpstreamTime         spanstat.SpanStat
	SemaphoreAcquireTime spanstat.SpanStat
	PolicyCheckTime      spanstat.SpanStat
	PolicyGenerationTime spanstat.SpanStat
	DataplaneTime        spanstat.SpanStat
	Success              bool
	Err                  error
	DataSource           accesslog.DNSDataSource
}

// IsTimeout return true if the ProxyRequest timeout
func (proxyStat *ProxyRequestContext) IsTimeout() bool {
	var neterr net.Error
	if errors.As(proxyStat.Err, &neterr) {
		return neterr.Timeout()
	}
	return false
}
