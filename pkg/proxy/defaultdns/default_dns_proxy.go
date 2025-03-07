// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package defaultdns

import (
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/lock"
)

// NewProxy instantiates the Proxy singleton.
func NewProxy() *Proxy {
	return &Proxy{
		mu: &lock.RWMutex{},
	}
}

// Proxy is the default dns proxy for
// the process.
type Proxy struct {
	mu    *lock.RWMutex
	proxy proxy.DNSProxier
}

// Set sets the DefaultDNSProxy
func (p *Proxy) Set(dnsProxy proxy.DNSProxier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxy = dnsProxy
}

// Get gets the DefaultDNSProxy
func (p *Proxy) Get() proxy.DNSProxier {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.proxy
}
