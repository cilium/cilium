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
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	log          = logging.DefaultLogger
	perFlowDebug = false
)

// Magic markers are attached to each packet. The lower 16 bits are used to
// identify packets which have gone through the proxy and to determine whether
// the packet is coming from a proxy at ingress or egress. The marking is
// compatible with Kubernetes's use of the packet mark.  The upper 16 bits can
// be used to carry the security identity.
const (
	magicMarkIngress int = 0x0FEA
	magicMarkEgress  int = 0x0FEB
	magicMarkK8sMasq int = 0x4000
	magicMarkK8sDrop int = 0x8000
)

// field names used while logging
const (
	fieldMarker          = "marker"
	fieldSocket          = "socket"
	fieldFd              = "fd"
	fieldProxyRedirectID = "id"

	// portReleaseDelay is the delay until a port is being released
	portReleaseDelay = time.Duration(5) * time.Minute

	// redirectCreationAttempts is the number of attempts to create a redirect
	redirectCreationAttempts = 5
)

type Redirect struct {
	// The following fields are only written to during initialization, it
	// is safe to read these fields without locking the mutex

	// ProxyPort is the port the redirects redirects to where the proxy is
	// listening on
	ProxyPort      uint16
	endpointID     uint64
	id             string
	ingress        bool
	port           uint16
	source         ProxySource
	parserType     policy.L7ParserType
	created        time.Time
	implementation RedirectImplementation

	// The following fields are updated while the redirect is alive, the
	// mutex must be held to read and write these fields
	mutex       lock.RWMutex
	lastUpdated time.Time
	rules       policy.L7DataMap
	stats       models.ProxyRedirectStatistics
}

func newRedirect(port uint16, source ProxySource, id string) *Redirect {
	return &Redirect{
		port:        port,
		source:      source,
		id:          id,
		created:     time.Now(),
		lastUpdated: time.Now(),
		stats: models.ProxyRedirectStatistics{
			Requests:  &models.MessageForwardingStatistics{},
			Responses: &models.MessageForwardingStatistics{},
		},
	}
}

func (r *Redirect) DeriveEndpointInfo(ip net.IP, info *accesslog.EndpointInfo) bool {
	if ep := endpointmanager.LookupIPv4(addressing.DeriveCiliumIPv4(ip).String()); ep != nil {
		ep.Mutex.RLock()
		defer ep.Mutex.RUnlock()

		info.ID = uint64(ep.ID)
		info.Labels = ep.GetLabels()
		info.LabelsSHA256 = ep.GetLabelsSHA()
		info.Identity = uint64(ep.GetIdentity())

		return true
	}

	return false
}

// GetObservationPoint returns the observation point at which the redirect is
// attached to
func (r *Redirect) GetObservationPoint() accesslog.ObservationPoint {
	if r.ingress {
		return accesslog.Ingress
	}

	return accesslog.Egress
}

// UpdateAccounting is called for each log record emitted as soon as the
// verdict is known
func (r *Redirect) UpdateAccounting(t accesslog.FlowType, verdict accesslog.FlowVerdict) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var stats *models.MessageForwardingStatistics

	switch t {
	case accesslog.TypeRequest:
		stats = r.stats.Requests
	case accesslog.TypeResponse:
		stats = r.stats.Responses
	default:
		return
	}

	stats.Received++

	switch verdict {
	case accesslog.VerdictForwarded:
		stats.Forwarded++
	case accesslog.VerdictDenied:
		stats.Denied++
	case accesslog.VerdictError:
		stats.Error++
	}
}

// RedirectImplementation is the generic proxy redirect interface that each
// proxy redirect type must implement
type RedirectImplementation interface {
	UpdateRules(wg *completion.WaitGroup) error
	Close(wg *completion.WaitGroup)
}

// GetMagicMark returns the magic marker with which each packet must be marked.
// The mark is different depending on whether the proxy is injected at ingress
// or egress.
func GetMagicMark(isIngress bool, identity int) int {
	mark := 0

	if isIngress {
		mark = magicMarkIngress
	} else {
		mark = magicMarkEgress
	}

	if identity != 0 {
		mark |= identity << 16
	}

	return mark
}

// ProxySource returns information about the endpoint being proxied.
type ProxySource interface {
	GetID() uint64
	RLock()
	RUnlock()
	Lock()
	Unlock()
	GetLabels() []string
	GetLabelsSHA() string
	GetIdentity() identityPkg.NumericIdentity
	GetIPv4Address() string
	GetIPv6Address() string
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

	// allocatedPorts is a map of all allocated proxy ports pointing
	// to the redirect rules attached to that port
	allocatedPorts map[uint16]*Redirect

	// redirects is a map of all redirect configurations indexed by
	// the redirect identifier. Redirects may be implemented by different
	// proxies.
	redirects map[string]*Redirect
}

// NewProxy creates a Proxy to keep track of redirects.
func NewProxy(minPort uint16, maxPort uint16) *Proxy {
	return &Proxy{
		rangeMin:       minPort,
		rangeMax:       maxPort,
		redirects:      make(map[string]*Redirect),
		allocatedPorts: make(map[uint16]*Redirect),
	}
}

var (
	portRandomizer      = rand.New(rand.NewSource(time.Now().UnixNano()))
	portRandomizerMutex lock.Mutex
)

func (p *Proxy) allocatePort() (uint16, error) {
	portRandomizerMutex.Lock()
	defer portRandomizerMutex.Unlock()

	for _, r := range portRandomizer.Perm(int(p.rangeMax - p.rangeMin + 1)) {
		resPort := uint16(r) + p.rangeMin

		if _, ok := p.allocatedPorts[resPort]; !ok {
			return resPort, nil
		}

	}

	return 0, fmt.Errorf("no available proxy ports")
}

var gcOnce sync.Once

// updateRules updates the rules of the redirect, Redirect.mutex must be held
func (r *Redirect) updateRules(l4 *policy.L4Filter) {
	r.rules = policy.L7DataMap{}
	for key, val := range l4.L7RulesPerEp {
		r.rules[key] = val
	}
}

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is already in place, only the rules will be
// updated.
func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, source ProxySource,
	notifier logger.LogRecordNotifier, wg *completion.WaitGroup) (*Redirect, error) {
	gcOnce.Do(func() {
		logger.SetNotifier(notifier)

		if lf := viper.GetString("access-log"); lf != "" {
			if err := logger.OpenLogfile(lf); err != nil {
				log.WithError(err).WithField(logger.FieldFilePath, lf).
					Warn("Cannot open L7 access log")
			}
		}

		if labels := viper.GetStringSlice("agent-labels"); len(labels) != 0 {
			logger.SetMetadata(labels)
		}

		go func() {
			for {
				time.Sleep(time.Duration(10) * time.Second)
				if deleted := proxymap.GC(); deleted > 0 {
					log.WithField("count", deleted).
						Debug("Evicted entries from proxy table")
				}
			}
		}()
	})

	p.mutex.Lock()
	defer p.mutex.Unlock()

	scopedLog := log.WithField(fieldProxyRedirectID, id)

	if r, ok := p.redirects[id]; ok {
		r.mutex.Lock()
		defer r.mutex.Unlock()

		if r.parserType != l4.L7Parser {
			return nil, fmt.Errorf("invalid type %q, must be of type %q", l4.L7Parser, r.parserType)
		}

		r.updateRules(l4)
		err := r.implementation.UpdateRules(wg)
		if err != nil {
			scopedLog.WithError(err).Error("Unable to update ", l4.L7Parser, " proxy")
			return nil, err
		}

		r.lastUpdated = time.Now()

		scopedLog.WithField(logfields.Object, logfields.Repr(r)).
			Debug("updated existing ", l4.L7Parser, " proxy instance")

		return r, nil
	}

	redir := newRedirect(uint16(l4.Port), source, id)
	redir.endpointID = source.GetID()
	redir.ingress = l4.Ingress
	redir.parserType = l4.L7Parser
	redir.updateRules(l4)

retryCreatePort:
	for nRetry := 0; ; nRetry++ {
		to, err := p.allocatePort()
		if err != nil {
			return nil, err
		}

		redir.ProxyPort = to

		switch l4.L7Parser {
		case policy.ParserTypeKafka:
			redir.implementation, err = createKafkaRedirect(redir, kafkaConfiguration{})

		case policy.ParserTypeHTTP:
			redir.implementation, err = createEnvoyRedirect(redir, wg)

		default:
			return nil, fmt.Errorf("unsupported L7 parser type: %s", l4.L7Parser)
		}

		switch {
		case err == nil:
			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("Created new ", l4.L7Parser, " proxy instance")

			p.allocatedPorts[to] = redir
			p.redirects[id] = redir

			break retryCreatePort

		// an error occurred, and we have no more retries
		case nRetry >= redirectCreationAttempts:
			scopedLog.WithError(err).Error("Unable to create ", l4.L7Parser, " proxy")
			return nil, err

		// an error ocurred and we can retry
		default:
			scopedLog.WithError(err).Warning("Unable to create ", l4.L7Parser, " proxy, will retry")
		}
	}

	return redir, nil
}

// RemoveRedirect removes an existing redirect.
func (p *Proxy) RemoveRedirect(id string, wg *completion.WaitGroup) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	r, ok := p.redirects[id]
	if !ok {
		return fmt.Errorf("unable to find redirect %s", id)
	}

	log.WithField(fieldProxyRedirectID, id).
		Debug("removing proxy redirect")
	r.implementation.Close(wg)

	delete(p.redirects, id)

	// delay the release and reuse of the port number so it is guaranteed
	// to be safe to listen on the port again
	go func() {
		time.Sleep(portReleaseDelay)

		// The cleanup of the proxymap is delayed a bit to ensure that
		// the datapath has implemented the redirect change and we
		// cleanup the map before we release the port and allow reuse
		proxymap.CleanupOnRedirectClose(r.ProxyPort)

		p.mutex.Lock()
		delete(p.allocatedPorts, r.ProxyPort)
		p.mutex.Unlock()

		log.WithField(fieldProxyRedirectID, id).Debugf("Delayed release of proxy port %d", r.ProxyPort)
	}()

	return nil
}

// UpdateNetworkPolicy adds or updates a network policy in the set
// published to L7 proxies.
func (p *Proxy) UpdateNetworkPolicy(ep envoy.NetworkPolicyEndpoint, policy *policy.L4Policy,
	labelsMap identityPkg.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identityPkg.NumericIdentity]bool, wg *completion.WaitGroup) error {
	return envoy.UpdateNetworkPolicy(ep, policy, labelsMap, deniedIngressIdentities, deniedEgressIdentities, wg)
}

// RemoveNetworkPolicy removes a network policy from the set published to
// L7 proxies.
func (p *Proxy) RemoveNetworkPolicy(ep envoy.NetworkPolicyEndpoint) {
	envoy.RemoveNetworkPolicy(ep)
}

// ChangeLogLevel changes proxy log level to correspond to the logrus log level 'level'.
func ChangeLogLevel(level logrus.Level) {
	if envoyProxy != nil {
		envoyProxy.ChangeLogLevel(level)
	}
}

func (r *Redirect) getLocation() string {
	if r.ingress {
		return "ingress"
	}

	return "egress"
}

func (r *Redirect) getRulesModel() []string {
	model := make([]string, len(r.rules))
	idx := 0
	for selector, rule := range r.rules {
		jsonSelector, _ := json.Marshal(selector)
		var jsonRule []byte

		switch r.parserType {
		case policy.ParserTypeHTTP:
			jsonRule, _ = json.Marshal(rule.HTTP)
		case policy.ParserTypeKafka:
			jsonRule, _ = json.Marshal(rule.Kafka)
		}

		model[idx] = fmt.Sprintf("from %s: %s", string(jsonSelector), string(jsonRule))
		idx++
	}
	return model
}

func getRedirectStatusModel(r *Redirect) *models.ProxyRedirectStatus {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	statsCopy := r.stats

	return &models.ProxyRedirectStatus{
		Protocol:           string(r.parserType),
		Port:               int64(r.port),
		AllocatedProxyPort: int64(r.ProxyPort),
		EndpointID:         int64(r.endpointID),
		EndpointLabels:     r.source.GetLabels(),
		Location:           r.getLocation(),
		Created:            strfmt.DateTime(r.created),
		LastUpdated:        strfmt.DateTime(r.lastUpdated),
		Rules:              r.getRulesModel(),
		Statistics:         &statsCopy,
	}
}

// getRedirectStatusModel returns the status of all redirects
func (p *Proxy) getRedirectsStatusModel() []*models.ProxyRedirectStatus {
	redirects := make([]*models.ProxyRedirectStatus, len(p.redirects))

	idx := 0
	for _, redirect := range p.redirects {
		redirects[idx] = getRedirectStatusModel(redirect)
		idx++
	}

	return redirects
}

// GetStatusModel returns the proxy status as API model
func (p *Proxy) GetStatusModel() *models.ProxyStatus {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return &models.ProxyStatus{
		IP:        node.GetInternalIPv4().String(),
		PortRange: fmt.Sprintf("%d-%d", p.rangeMin, p.rangeMax),
		Redirects: p.getRedirectsStatusModel(),
	}
}

// removeProxyMapEntryOnClose is called after the proxy has closed a connection
// and will remove the proxymap entry for that connection
func (r *Redirect) removeProxyMapEntryOnClose(c net.Conn) error {
	key, err := getProxyMapKey(c, r.ProxyPort)
	if err != nil {
		return fmt.Errorf("unable to extract proxymap key: %s", err)
	}

	return proxymap.Delete(key)
}

// LocalEndpointInfo return an EndpointInfo with the information of the local endpoint
func (r *Redirect) LocalEndpointInfo() accesslog.EndpointInfo {
	source := r.source
	info := accesslog.EndpointInfo{}

	source.RLock()
	info.ID = source.GetID()
	info.IPv4 = source.GetIPv4Address()
	info.IPv6 = source.GetIPv6Address()
	info.Labels = source.GetLabels()
	info.LabelsSHA256 = source.GetLabelsSHA()
	info.Identity = uint64(source.GetIdentity())
	source.RUnlock()

	return info
}
