// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaultdns

import (
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/lock"
)

// NewProxy instantiates the Proxy singleton.
func NewProxy() Proxy {
	return &defaultProxy{
		mu: &lock.RWMutex{},
	}
}

// Proxy represents the interface setting
// and getting the default dns proxy. It
// is an interface so that it can be mocked.
type Proxy interface {
	Get() proxy.DNSProxier
	Set(proxy.DNSProxier)
}

// defaultProxy is the default dns proxy getter
// and setter for the process.
type defaultProxy struct {
	mu    *lock.RWMutex
	proxy proxy.DNSProxier
}

// Set sets the DefaultDNSProxy
func (p *defaultProxy) Set(dnsProxy proxy.DNSProxier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxy = dnsProxy
}

// Get gets the DefaultDNSProxy
func (p *defaultProxy) Get() proxy.DNSProxier {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.proxy
}
