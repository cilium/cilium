// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gr

import "github.com/osrg/gobgp/v4/pkg/packet/bgp"

// Restart keeps the graceful restart of this speaker: we are the Restarting
// Speaker of RFC 4724 Section 4.1. Like Helper it does no I/O: the caller
// passes events and runs the actions that come back, including the timers.
// There is one Restart for the whole speaker, because what it keeps spans
// the peers.
//
// RFC 4724 Section 4.1: "it MUST defer route selection for an address family
// until it either (a) receives the End-of-RIB marker from all its peers
// (excluding the ones with the "Restart State" bit set in the received
// capability and excluding the ones that do not advertise the graceful
// restart capability) or (b) the Selection_Deferral_Timer referred to below
// has expired."
//
// Each family is in one of these phases:
//
//	             PeerAdded                    last peer removed
//	+-------------+ -------> +-----------+ -------------------> +----------+
//	| not started |          |  Waiting  |                      | Released |
//	+-------------+          +-----------+                      +----------+
//
// A family that was never waited for is not kept. Waiting keeps the peers
// whose End-of-RIB marker is awaited. A peer leaves the set when its marker
// is received, when its timer expires, when the session is established
// without the Graceful Restart Capability or with the Restart State bit, when
// its session ends, or when the peer is removed. When the set becomes empty,
// the family is released: the caller advertises the family to its peers,
// with the End-of-RIB marker. A peer added after that is not waited for in
// that family. The restart is over when no family waits any more. A peer
// added after that is not waited for at all, also in a family that was
// never waited for: otherwise a peer added long after the restart, with a
// family the others do not have, would hold that family back.
//
// The caller passes PeerAdded for each peer that takes part, before the
// other events of the peer. Events of a peer that is not waited for do
// nothing. The timers need no ID, unlike the ones of Helper: an expiry that
// comes late, after the peer left the family, finds nothing to do. When a
// peer is added again while its old timer is about to expire, the late
// expiry ends the new wait for the peer early. That is harmless.
type Restart struct {
	families map[bgp.Family]*deferredFamily
	// over is set when the last waiting family is released. The restart
	// does not start again.
	over bool
}

// deferredFamily is a family in Waiting or Released.
type deferredFamily struct {
	// waiting is the peers whose End-of-RIB marker is awaited. The family
	// is released when it is empty.
	waiting map[string]struct{}
}

func (d *deferredFamily) released() bool {
	return len(d.waiting) == 0
}

// DeferralTimer names a Selection_Deferral_Timer: one runs for each peer
// and family whose End-of-RIB marker is awaited.
type DeferralTimer struct {
	Peer   string
	Family bgp.Family
}

// RestartActions is what the caller must do after an event of Restart, in
// the order of the fields. It is a return value: each event method of
// Restart returns it.
type RestartActions struct {
	// StopTimers: stop these timers.
	StopTimers []DeferralTimer
	// StartTimers: start these timers, with the deferral time of the
	// peer. Only PeerAdded returns them.
	StartTimers []DeferralTimer
	// Released: advertise these families to the peers, with the End-of-RIB
	// marker.
	Released []bgp.Family
}

// Restarting reports whether some family is waiting. A family is added
// only with a peer that is waited for, and over is set when the last
// family is released, so no loop is needed.
func (r *Restart) Restarting() bool {
	return len(r.families) > 0 && !r.over
}

// waiting reports whether some family is waiting, by looking.
func (r *Restart) waiting() bool {
	for _, d := range r.families {
		if !d.released() {
			return true
		}
	}
	return false
}

// Deferred reports whether family f is waiting: its routes are not
// advertised yet.
func (r *Restart) Deferred(f bgp.Family) bool {
	d, ok := r.families[f]
	return ok && !d.released()
}

// remove stops waiting for peer p in family f, if it waits. The family is
// released if p was the last peer.
func (r *Restart) remove(p string, f bgp.Family, d *deferredFamily, stopTimer bool, a *RestartActions) {
	if _, ok := d.waiting[p]; !ok {
		return
	}
	if stopTimer {
		a.StopTimers = append(a.StopTimers, DeferralTimer{Peer: p, Family: f})
	}
	delete(d.waiting, p)
	if d.released() {
		a.Released = append(a.Released, f)
		r.over = !r.waiting()
	}
}

// removeAll stops waiting for peer p in every family.
func (r *Restart) removeAll(p string, a *RestartActions) {
	for f, d := range r.families {
		r.remove(p, f, d, true, a)
	}
}

// PeerAdded is called when peer p takes part in the restart: its End-of-RIB
// marker is awaited for each of families, until the timer of the family
// expires at most. A family that is already released is not waited for
// again, and nothing is waited for when the restart is over.
func (r *Restart) PeerAdded(p string, families []bgp.Family) RestartActions {
	var a RestartActions
	if r.over {
		return a
	}
	if r.families == nil {
		r.families = make(map[bgp.Family]*deferredFamily)
	}
	for _, f := range families {
		d, ok := r.families[f]
		if !ok {
			d = &deferredFamily{waiting: make(map[string]struct{})}
			r.families[f] = d
		} else if d.released() {
			continue
		}
		if _, ok := d.waiting[p]; ok {
			continue
		}
		d.waiting[p] = struct{}{}
		a.StartTimers = append(a.StartTimers, DeferralTimer{Peer: p, Family: f})
	}
	return a
}

// PeerRemoved is called when peer p is removed.
func (r *Restart) PeerRemoved(p string) RestartActions {
	var a RestartActions
	r.removeAll(p, &a)
	return a
}

// PeerEstablished is called when the session of peer p is established. n is
// what the session negotiated.
//
// RFC 4724 Section 4.1 excludes "the ones with the "Restart State" bit set
// in the received capability" and "the ones that do not advertise the
// graceful restart capability" from the peers whose End-of-RIB marker is
// awaited. The marker of the other peers is awaited for each family that
// the session negotiated. RFC 4724 Section 2: "The End-of-RIB marker MUST be
// sent by a BGP speaker to its peer once it completes the initial routing
// update (including the case when there is no update to send) for an
// address family after the BGP session is established."
func (r *Restart) PeerEstablished(p string, n Negotiated) RestartActions {
	var a RestartActions
	if n.GR == nil || n.GR.Flags&restartStateBit != 0 {
		r.removeAll(p, &a)
		return a
	}
	for f, d := range r.families {
		if !n.Families[f] {
			r.remove(p, f, d, true, &a)
		}
	}
	return a
}

// EORReceived is called when the End-of-RIB marker of family f is received
// from peer p.
func (r *Restart) EORReceived(p string, f bgp.Family) RestartActions {
	var a RestartActions
	if d, ok := r.families[f]; ok {
		r.remove(p, f, d, true, &a)
	}
	return a
}

// PeerDown is called when the session of peer p ends. The marker of the
// peer is not awaited any more: RFC 4724 does not say so, but a session
// that ends during the restart would delay every peer by its reconnection.
func (r *Restart) PeerDown(p string) RestartActions {
	var a RestartActions
	r.removeAll(p, &a)
	return a
}

// TimerExpired is called when the timer of peer p and family f expires.
func (r *Restart) TimerExpired(p string, f bgp.Family) RestartActions {
	var a RestartActions
	if d, ok := r.families[f]; ok {
		r.remove(p, f, d, false, &a)
	}
	return a
}
