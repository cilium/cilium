// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package speaker

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"
	"strconv"
	"time"

	"go.universe.tf/metallb/pkg/bgp"
	"go.universe.tf/metallb/pkg/config"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/go-kit/kit/log"
)

type Peer struct {
	cfg *config.Peer
	BGP Session
}

type BGPController struct {
	Logger     log.Logger
	MyNode     string
	nodeLabels labels.Set
	Peers      []*Peer
	SvcAds     map[string][]*bgp.Advertisement
}

func (c *BGPController) SetConfig(l log.Logger, cfg *config.Config) error {
	newPeers := make([]*Peer, 0, len(cfg.Peers))
newPeers:
	for _, p := range cfg.Peers {
		for i, ep := range c.Peers {
			if ep == nil {
				continue
			}
			if reflect.DeepEqual(p, ep.cfg) {
				newPeers = append(newPeers, ep)
				c.Peers[i] = nil
				continue newPeers
			}
		}
		// No existing peers match, create a new one.
		newPeers = append(newPeers, &Peer{
			cfg: p,
		})
	}

	oldPeers := c.Peers
	c.Peers = newPeers

	for _, p := range oldPeers {
		if p == nil {
			continue
		}
		l.Log("event", "peerRemoved", "peer", p.cfg.Addr, "reason", "removedFromConfig", "msg", "peer deconfigured, closing BGP session")
		if p.BGP != nil {
			if err := p.BGP.Close(); err != nil {
				l.Log("op", "setConfig", "error", err, "peer", p.cfg.Addr, "msg", "failed to shut down BGP session")
			}
		}
	}

	return c.syncPeers(l)
}

// hasHealthyEndpoint return true if this node has at least one healthy endpoint.
// It only checks nodes matching the given filterNode function.
func hasHealthyEndpoint(eps *Endpoints, filterNode func(*string) bool) bool {
	ready := map[string]bool{}
	for _, ep := range eps.Ready {
		if filterNode(ep.NodeName) {
			continue
		}
		if _, ok := ready[ep.IP]; !ok {
			// Only set true if nothing else has expressed an
			// opinion. This means that false will take precedence
			// if there's any unready ports for a given endpoint.
			ready[ep.IP] = true
		}
	}
	for _, ep := range eps.NotReady {
		ready[ep.IP] = false
	}

	for _, r := range ready {
		if r {
			// At least one fully healthy endpoint on this machine.
			return true
		}
	}
	return false
}

func (c *BGPController) ShouldAnnounce(l log.Logger, name string, policyType string, eps *Endpoints) string {
	// Should we advertise?
	// Yes, if externalTrafficPolicy is
	//  Cluster && any healthy endpoint exists
	// or
	//  Local && there's a ready local endpoint.
	filterNode := func(toFilter *string) bool {
		if toFilter == nil || *toFilter != c.MyNode {
			return true
		}
		return false
	}

	if v1.ServiceExternalTrafficPolicyType(policyType) == v1.ServiceExternalTrafficPolicyTypeLocal && !hasHealthyEndpoint(eps, filterNode) {
		return "noLocalEndpoints"
	} else if !hasHealthyEndpoint(eps, func(toFilter *string) bool { return false }) {
		return "noEndpoints"
	}
	return ""
}

// Called when either the peer list or node labels have changed,
// implying that the set of running BGP sessions may need tweaking.
func (c *BGPController) syncPeers(l log.Logger) error {
	var (
		errs          int
		needUpdateAds bool
	)
	for _, p := range c.Peers {
		// First, determine if the peering should be active for this
		// node.
		shouldRun := false
		for _, ns := range p.cfg.NodeSelectors {
			if ns.Matches(c.nodeLabels) {
				shouldRun = true
				break
			}
		}

		// Now, compare current state to intended state, and correct.
		if p.BGP != nil && !shouldRun {
			// Oops, session is running but shouldn't be. Shut it down.
			l.Log("event", "peerRemoved", "peer", p.cfg.Addr, "reason", "filteredByNodeSelector", "msg", "peer deconfigured, closing BGP session")
			if err := p.BGP.Close(); err != nil {
				l.Log("op", "syncPeers", "error", err, "peer", p.cfg.Addr, "msg", "failed to shut down BGP session")
			}
			p.BGP = nil
		} else if p.BGP == nil && shouldRun {
			// Session doesn't exist, but should be running. Create
			// it.
			l.Log("event", "peerAdded", "peer", p.cfg.Addr, "msg", "peer configured, starting BGP session")
			var routerID net.IP
			if p.cfg.RouterID != nil {
				routerID = p.cfg.RouterID
			}
			s, err := newBGP(c.Logger, net.JoinHostPort(p.cfg.Addr.String(), strconv.Itoa(int(p.cfg.Port))), p.cfg.MyASN, routerID, p.cfg.ASN, p.cfg.HoldTime, p.cfg.Password, c.MyNode)
			if err != nil {
				l.Log("op", "syncPeers", "error", err, "peer", p.cfg.Addr, "msg", "failed to create BGP session")
				errs++
			} else {
				p.BGP = s
				needUpdateAds = true
			}
		}
	}
	if needUpdateAds {
		// Some new sessions came up, resync advertisement state.
		if err := c.UpdateAds(); err != nil {
			l.Log("op", "updateAds", "error", err, "msg", "failed to update BGP advertisements")
			return err
		}
	}
	if errs > 0 {
		return fmt.Errorf("%d BGP sessions failed to start", errs)
	}
	return nil
}

func (c *BGPController) SetBalancer(l log.Logger, name string, lbIP net.IP, pool *config.Pool) error {
	c.SvcAds[name] = nil
	for _, adCfg := range pool.BGPAdvertisements {
		m := net.CIDRMask(adCfg.AggregationLength, 32)
		ad := &bgp.Advertisement{
			Prefix: &net.IPNet{
				IP:   lbIP.Mask(m),
				Mask: m,
			},
			LocalPref: adCfg.LocalPref,
		}
		for comm := range adCfg.Communities {
			ad.Communities = append(ad.Communities, comm)
		}
		sort.Slice(ad.Communities, func(i, j int) bool { return ad.Communities[i] < ad.Communities[j] })
		c.SvcAds[name] = append(c.SvcAds[name], ad)
	}

	if err := c.UpdateAds(); err != nil {
		return err
	}

	l.Log("event", "updatedAdvertisements", "numAds", len(c.SvcAds[name]), "msg", "making advertisements using BGP")

	return nil
}

func (c *BGPController) UpdateAds() error {
	var allAds []*bgp.Advertisement
	for _, ads := range c.SvcAds {
		// This list might contain duplicates, but that's fine,
		// they'll get compacted by the session code when it's
		// calculating advertisements.
		//
		// TODO: be more intelligent about compacting advertisements
		// and detecting conflicting advertisements.
		allAds = append(allAds, ads...)
	}
	for _, session := range c.PeerSessions() {
		if session == nil {
			continue
		}
		if err := session.Set(allAds...); err != nil {
			return err
		}
	}
	return nil
}

func (c *BGPController) DeleteBalancer(l log.Logger, name, reason string) error {
	if _, ok := c.SvcAds[name]; !ok {
		return nil
	}
	delete(c.SvcAds, name)
	return c.UpdateAds()
}

// Session gives access to the BGP session.
type Session interface {
	io.Closer
	Set(advs ...*bgp.Advertisement) error
}

func (c *BGPController) SetNodeLabels(l log.Logger, lbls map[string]string) error {
	if lbls == nil {
		lbls = map[string]string{}
	}
	ns := labels.Set(lbls)
	if c.nodeLabels != nil && labels.Equals(c.nodeLabels, ns) {
		// Node labels unchanged, no action required.
		return nil
	}
	c.nodeLabels = ns
	l.Log("event", "nodeLabelsChanged", "msg", "Node labels changed, resyncing BGP peers")
	return c.syncPeers(l)
}

// PeerSessions returns the underlying BGP sessions for direct use.
func (c *BGPController) PeerSessions() []Session {
	s := make([]Session, len(c.Peers))
	for i, peer := range c.Peers {
		s[i] = peer.BGP
	}
	return s
}

var newBGP = func(logger log.Logger, addr string, myASN uint32, routerID net.IP, asn uint32, hold time.Duration, password string, myNode string) (Session, error) {
	return bgp.New(logger, addr, myASN, routerID, asn, hold, password, myNode)
}
