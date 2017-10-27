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
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Magic markers are attached to each packet. The upper 16 bits are used to
// identify packets which have gone through the proxy and to determine whether
// the packet is coming from a proxy at ingress or egress. The lower 16 bits
// can be used to carry the security identity.
const (
	magicMarkIngress int = 0xFEFA << 16
	magicMarkEgress  int = 0xFEFB << 16
)

// field names used while logging
const (
	fieldMarker          = "marker"
	fieldSocket          = "socket"
	fieldFd              = "fd"
	fieldProxyRedirectID = "id"
	fieldProxyKind       = "kind"
)

// Supported proxy types
const (
	ProxyKindOxy   = "oxy"
	ProxyKindEnvoy = "envoy"
)

// Redirect is the generic proxy redirect interface that each proxy redirect type must export
type Redirect interface {
	ToPort() uint16
	UpdateRules(l4 *policy.L4Filter) error
	Close()
}

// GetMagicMark returns the magic marker with which each packet must be marked.
// The mark is different depending on whether the proxy is injected at ingress
// or egress.
func GetMagicMark(isIngress bool) int {
	if isIngress {
		return magicMarkIngress
	}

	return magicMarkEgress
}

// ProxySource returns information about the endpoint being proxied.
type ProxySource interface {
	GetID() uint64
	RLock()
	GetLabels() []string
	GetLabelsSHA() string
	GetIdentity() policy.NumericIdentity
	ResolveIdentity(policy.NumericIdentity) *policy.Identity
	GetIPv4Address() string
	GetIPv6Address() string
	RUnlock()
}

// Proxy maintains state about redirects
type Proxy struct {
	// mutex is the lock required when modifying any proxy datastructure
	mutex lock.RWMutex

	// rangeMin is the minimum port used for proxy port allocation
	rangeMin uint16

	// rangeMax is the maximum port used for proxy port allocation.
	// If port is unspecified, the proxy will automatically allocate
	// ports out of the rangeMin-rangeMax range.
	rangeMax uint16

	// nextPort is the next available proxy port to use
	nextPort uint16

	// allocatedPorts is a map of all allocated proxy ports pointing
	// to the redirect rules attached to that port
	allocatedPorts map[uint16]Redirect

	// redirects is a map of all redirect configurations indexed by
	// the redirect identifier. Redirects may be implemented by different
	// proxies.
	redirects map[string]Redirect
}

// NewProxy creates a Proxy to keep track of redirects.
func NewProxy(minPort uint16, maxPort uint16) *Proxy {
	return &Proxy{
		rangeMin:       minPort,
		rangeMax:       maxPort,
		nextPort:       minPort,
		redirects:      make(map[string]Redirect),
		allocatedPorts: make(map[uint16]Redirect),
	}
}

func (p *Proxy) allocatePort() (uint16, error) {
	port := p.nextPort

	for {
		resPort := port
		port++
		if port >= p.rangeMax {
			port = p.rangeMin
		}

		if _, ok := p.allocatedPorts[resPort]; !ok {
			return resPort, nil
		}

		if port == p.nextPort {
			return 0, fmt.Errorf("no available proxy ports")
		}
	}
}

var gcOnce sync.Once

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is already in place, only the rules will be
// updated.
func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, source ProxySource, kind string) (Redirect, error) {
	scopedLog := log.WithFields(log.Fields{
		fieldProxyRedirectID: id,
		fieldProxyKind:       kind,
	})

	gcOnce.Do(func() {
		if lf := viper.GetString("access-log"); lf != "" {
			if err := accesslog.OpenLogfile(lf); err != nil {
				scopedLog.WithError(err).WithField(accesslog.FieldFilePath, lf).Warn("Cannot open L7 access log")
			}
		}

		if labels := viper.GetStringSlice("agent-labels"); len(labels) != 0 {
			accesslog.SetMetadata(labels)
		}

		go func() {
			for {
				time.Sleep(time.Duration(10) * time.Second)
				if deleted := GC(); deleted > 0 {
					scopedLog.WithField("count", deleted).Debug("Evicted entries from proxy table")
				}
			}
		}()
	})

	p.mutex.Lock()
	defer p.mutex.Unlock()

	if r, ok := p.redirects[id]; ok {
		err := r.UpdateRules(l4)
		if err != nil {
			return nil, err
		}
		scopedLog.WithField(logfields.Object, logfields.Repr(r)).Debug("updated existing proxy instance")
		return r, nil
	}

	to, err := p.allocatePort()
	if err != nil {
		return nil, err
	}

	var redir Redirect

	switch l4.L7Parser {
	case policy.ParserTypeKafka:
		redir, err = createKafkaRedirect(kafkaConfiguration{
			policy:     l4,
			id:         id,
			source:     source,
			listenPort: to})
		scopedLog.WithField(logfields.Object, logfields.Repr(redir)).Debug("Created new kafka proxy instance")
	case policy.ParserTypeHTTP:
		switch kind {
		case ProxyKindOxy:
			redir, err = createOxyRedirect(l4, id, source, to)
		default:
			return nil, fmt.Errorf("Unknown proxy kind: %s", kind)
		}

		scopedLog.WithField(logfields.Object, logfields.Repr(redir)).Debug("Created new proxy instance")
	}
	if err != nil {
		scopedLog.WithError(err).Error("Unable to create proxy of kind")
		return nil, err
	}

	p.allocatedPorts[to] = redir
	p.redirects[id] = redir

	return redir, nil
}

// RemoveRedirect removes an existing redirect.
func (p *Proxy) RemoveRedirect(id string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	r, ok := p.redirects[id]
	if !ok {
		return fmt.Errorf("unable to find redirect %s", id)
	}

	log.WithField(fieldProxyRedirectID, id).Debug("removing proxy redirect")
	toPort := r.ToPort()
	r.Close()

	delete(p.redirects, id)
	delete(p.allocatedPorts, toPort)

	return nil
}
