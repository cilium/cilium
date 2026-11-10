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

import (
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Phase is the phase of the graceful restart of one family of a peer. It is
// a return value: Helper.Phase() returns it.
type Phase uint8

const (
	// None: the stale routes of the family are not kept. Phase() returns
	// it for a family that is not in Helper.families. It is never stored.
	None Phase = iota
	// Stale: the stale routes are kept for the Restart Time, or until the
	// End-of-RIB marker on the new session (RFC 4724 Section 4.2).
	Stale
	// LLGRStale: the stale routes are kept for the Long-Lived Stale Time
	// (RFC 9494 Section 4.2).
	LLGRStale
)

func (p Phase) String() string {
	switch p {
	case None:
		return "none"
	case Stale:
		return "stale"
	case LLGRStale:
		return "llgr-stale"
	}
	return "unknown"
}

// restartingFamily is a family whose stale routes are kept. A family in None
// is not in Helper.families.
type restartingFamily struct {
	phase Phase
	// llst is the Long-Lived Stale Time that the peer advertised for the
	// family in the session that ended. Zero means no long-lived graceful
	// restart.
	llst uint32
	// llgrTimerID identifies the LLST timer that runs for the family. Zero
	// means that it does not run.
	llgrTimerID uint64
}

// RestartTimer is the Restart Time timer to start. It is a return value:
// part of Actions.
type RestartTimer struct {
	Duration time.Duration
	ID       uint64
}

// LLGRTimer is an LLST timer to start. It is a return value: part of
// Actions.
type LLGRTimer struct {
	Family   bgp.Family
	Duration time.Duration
	ID       uint64
}

// Actions is what the caller must do after an event, in the order of the
// fields. It is a return value: each event method of Helper returns it.
//
// Each timer has an ID. When a timer expires, the caller passes its ID to
// TimerExpired() or LLGRTimerExpired(). An expiry with another ID comes
// from a timer that was stopped too late, and it is ignored.
type Actions struct {
	// DropStale: remove the stale routes of these families.
	DropStale []bgp.Family
	// MarkStale: mark the routes of these families stale.
	MarkStale []bgp.Family
	// MarkLLGRStale: attach LLGR_STALE to the stale routes of these
	// families that do not have it yet, and remove the ones with NO_LLGR.
	MarkLLGRStale []bgp.Family
	// StopRestartTimer: stop the Restart Time timer.
	StopRestartTimer bool
	// StopLLGRTimers: stop the LLST timers of these families.
	StopLLGRTimers []bgp.Family
	// StartRestartTimer: start the Restart Time timer, if not nil.
	StartRestartTimer *RestartTimer
	// StartLLGRTimers: start these LLST timers.
	StartLLGRTimers []LLGRTimer
}

// Helper keeps the graceful restart state of each family of one peer. Each
// method takes an event and returns the actions for the caller. The caller
// must serialize the calls. The zero value is ready to use.
//
// Each family of the peer is in one of these phases:
//
//	          SessionDown
//	+------+ ---------------------> +-----------+ <--+ SessionDown
//	|      |                        |   Stale   |    |   (old stale removed)
//	|      | <--------------------- |           | ---+ SessionEstablished
//	|      |  EORReceived           +-----------+        (preserved)
//	|      |  SessionEstablished          |
//	|      |    (not preserved)           | TimerExpired
//	| None |  TimerExpired                |   (LLST > 0)
//	|      |    (LLST == 0)               v
//	|      |                        +-----------+ <--+ SessionDown
//	|      | <--------------------- | LLGRStale |    |   (old stale kept,
//	|      |  EORReceived           |           | ---+   timer not updated)
//	|      |  LLGRTimerExpired      +-----------+      SessionEstablished
//	+------+  SessionEstablished                         (preserved)
//	            (not preserved)
//
// A family that is in the Long-Lived Graceful Restart Capability but not in
// the Graceful Restart Capability has a Restart Time of zero. SessionDown
// moves it from None to LLGRStale at once.
//
// Abort, and SessionDown without the family, move a family from Stale or
// LLGRStale to None without removing its routes. The caller removes them.
//
// A family in None is not kept by Helper. Every transition to None goes
// through untrack(): the family is removed from Helper, and its LLST timer is
// stopped. When the restart of a family ends by the procedures of RFC 4724
// or RFC 9494, for example at its End-of-RIB marker or at a timer, finish()
// also has the caller remove its stale routes. When it ends for another
// reason, the caller removes all its routes itself, and untrack() is used
// alone.
//
// The Restart Time timer belongs to the peer. It runs from SessionDown
// until SessionEstablished, TimerExpired or Abort. Each family in LLGRStale
// has its own LLST timer.
//
// SessionEstablished and SessionDown alternate, starting with
// SessionEstablished, and EORReceived comes while the session is
// established. A call out of this order is a bug of the caller, and it
// panics. The timers expire on their own: an expiry whose ID is not the one
// of the running timer is ignored, but an ID of zero is never issued, and it
// panics too.
type Helper struct {
	// up is true while the session is established.
	up       bool
	families map[bgp.Family]*restartingFamily
	// restartTimerID identifies the Restart Time timer that runs. Zero
	// means that it does not run.
	restartTimerID uint64
	lastTimerID    uint64
}

// Restarting reports whether the peer restarts gracefully: the stale routes
// of some family are kept.
func (h *Helper) Restarting() bool {
	return len(h.families) > 0
}

// Phase returns the phase of family f.
func (h *Helper) Phase(f bgp.Family) Phase {
	if r, ok := h.families[f]; ok {
		return r.phase
	}
	return None
}

func (h *Helper) newTimerID() uint64 {
	h.lastTimerID++
	return h.lastTimerID
}

func (h *Helper) stopRestartTimer(a *Actions) {
	if h.restartTimerID != 0 {
		a.StopRestartTimer = true
		h.restartTimerID = 0
	}
}

// stopLLGRTimer stops the LLST timer of family f if it runs.
func (h *Helper) stopLLGRTimer(f bgp.Family, r *restartingFamily, a *Actions) {
	if r.llgrTimerID != 0 {
		a.StopLLGRTimers = append(a.StopLLGRTimers, f)
		r.llgrTimerID = 0
	}
}

// untrack makes Helper stop tracking family f. Its LLST timer is stopped.
// Its routes are left to the caller.
func (h *Helper) untrack(f bgp.Family, r *restartingFamily, a *Actions) {
	h.stopLLGRTimer(f, r, a)
	delete(h.families, f)
}

// startLLGR moves family f to the long-lived stale period: the stale routes
// get LLGR_STALE, and its LLST timer starts. r.llst must not be zero.
func (h *Helper) startLLGR(f bgp.Family, r *restartingFamily, a *Actions) {
	r.phase = LLGRStale
	r.llgrTimerID = h.newTimerID()
	a.MarkLLGRStale = append(a.MarkLLGRStale, f)
	a.StartLLGRTimers = append(a.StartLLGRTimers, LLGRTimer{
		Family:   f,
		Duration: time.Duration(r.llst) * time.Second,
		ID:       r.llgrTimerID,
	})
}

// finish ends the restart of family f by the procedures of RFC 4724 or
// RFC 9494. Its stale routes are removed, and its LLST timer is stopped.
func (h *Helper) finish(f bgp.Family, r *restartingFamily, a *Actions) {
	h.untrack(f, r, a)
	a.DropStale = append(a.DropStale, f)
}

// SessionDown is called when the session ends. n is what the session
// negotiated. When the session does not end as a graceful restart, the
// caller passes n without the Graceful Restart Capability.
//
// RFC 4724 Section 4.2: "When the Receiving Speaker detects termination of
// the TCP session for a BGP session with a peer that has advertised the
// Graceful Restart Capability, it MUST retain the routes received from the
// peer for all the address families that were previously received in the
// Graceful Restart Capability and MUST mark them as stale routing
// information." The caller removes the routes of the other families itself.
func (h *Helper) SessionDown(n Negotiated) Actions {
	if !h.up {
		panic("gr: SessionDown while the session is not established")
	}
	h.up = false
	var a Actions
	// families maps each family whose routes are kept as stale to its
	// LLST, or zero. llgrOnly maps each family that is only in the
	// Long-Lived Graceful Restart Capability to its LLST.
	var families, llgrOnly map[bgp.Family]uint32
	var restartTime time.Duration
	if n.GR != nil {
		families = make(map[bgp.Family]uint32)
		llgrOnly = make(map[bgp.Family]uint32)
		gr := n.grFamilies()
		llgr := n.llgrTuples()
		for f := range gr {
			if t, ok := llgr[f]; ok {
				families[f] = t.RestartTime
			} else {
				families[f] = 0
			}
		}
		// RFC 9494 Section 4.2: "If the Graceful Restart Capability that
		// was received does not list all AFIs/SAFIs supported by the
		// session, then the GR Restart Time shall be deemed zero for
		// those AFIs/SAFIs that are not listed." and "For example, if the
		// Restart Time is zero and the Long-Lived Stale Time is nonzero,
		// only the procedures particular to LLGR would apply." With an
		// LLST of zero too, "none of these procedures would apply".
		for f, t := range llgr {
			if _, ok := gr[f]; !ok && t.RestartTime != 0 {
				llgrOnly[f] = t.RestartTime
			}
		}
		restartTime = time.Duration(n.GR.Time) * time.Second
	}
	// The session ended before the last restart was over. The caller
	// removes the routes of a family that is not kept.
	for f, r := range h.families {
		_, ok := families[f]
		_, ok2 := llgrOnly[f]
		if !ok && !ok2 {
			h.untrack(f, r, &a)
		}
	}
	if len(families)+len(llgrOnly) > 0 && h.families == nil {
		h.families = make(map[bgp.Family]*restartingFamily)
	}
	stale := false
	for f, llst := range families {
		a.MarkStale = append(a.MarkStale, f)
		r, ok := h.families[f]
		if !ok {
			h.families[f] = &restartingFamily{phase: Stale, llst: llst}
			stale = true
			continue
		}
		switch r.phase {
		case Stale:
			// RFC 4724 Section 4.2: "To deal with possible consecutive
			// restarts, a route (from the peer) previously marked as
			// stale MUST be deleted."
			a.DropStale = append(a.DropStale, f)
			r.llst = llst
			stale = true
		case LLGRStale:
			// RFC 9494 Section 4.2: "However, in the case of consecutive
			// restarts, the previously marked stale routes MUST NOT be
			// deleted before the timer for the Long-Lived Stale Time
			// expires." and "If a Long-Lived Stale Time timer is running
			// for routes with a given AFI/SAFI received from a peer, it
			// MUST NOT be updated (other than by manual operator
			// intervention) until the peer has established and
			// synchronized a new session."
			//
			// The routes received on the session that ended become stale
			// too, and get LLGR_STALE: "The helper router MUST attach the
			// LLGR_STALE community to the stale routes being retained."
			a.MarkLLGRStale = append(a.MarkLLGRStale, f)
		}
	}
	// A family only in the Long-Lived Graceful Restart Capability starts
	// its long-lived stale period at once.
	for f, llst := range llgrOnly {
		a.MarkStale = append(a.MarkStale, f)
		if _, ok := h.families[f]; ok {
			// The family is in LLGRStale. A family in Stale is not here:
			// SessionEstablished ended its restart unless it is in the
			// Graceful Restart Capability of the session. As above, the
			// old stale routes are kept, and the timer is not updated.
			a.MarkLLGRStale = append(a.MarkLLGRStale, f)
			continue
		}
		r := &restartingFamily{llst: llst}
		h.families[f] = r
		h.startLLGR(f, r, &a)
	}
	if stale {
		h.restartTimerID = h.newTimerID()
		a.StartRestartTimer = &RestartTimer{Duration: restartTime, ID: h.restartTimerID}
	}
	return a
}

// TimerExpired is called when the Restart Time timer id expires before the
// session is established again. RFC 4724 Section 4.2: "If the session does
// not get re-established within the "Restart Time" that the peer advertised
// previously, the Receiving Speaker MUST delete all the stale routes from the
// peer that it is retaining." A family with an LLST moves to the long-lived
// stale period instead (RFC 9494 Section 4.2).
func (h *Helper) TimerExpired(id uint64) Actions {
	if id == 0 {
		panic("gr: TimerExpired with ID 0")
	}
	var a Actions
	if id != h.restartTimerID {
		return a
	}
	h.restartTimerID = 0
	for f, r := range h.families {
		if r.phase != Stale {
			continue
		}
		if r.llst == 0 {
			h.finish(f, r, &a)
			continue
		}
		h.startLLGR(f, r, &a)
	}
	return a
}

// LLGRTimerExpired is called when the LLST timer id of family f expires.
func (h *Helper) LLGRTimerExpired(f bgp.Family, id uint64) Actions {
	if id == 0 {
		panic("gr: LLGRTimerExpired with ID 0")
	}
	var a Actions
	r, ok := h.families[f]
	if !ok || r.phase != LLGRStale || r.llgrTimerID != id {
		return a
	}
	// The timer has already fired.
	r.llgrTimerID = 0
	h.finish(f, r, &a)
	return a
}

// SessionEstablished is called when the session is established. n is what
// the session negotiated.
func (h *Helper) SessionEstablished(n Negotiated) Actions {
	if h.up {
		panic("gr: SessionEstablished while the session is established")
	}
	h.up = true
	var a Actions
	h.stopRestartTimer(&a)
	gr := n.grFamilies()
	llgr := n.llgrTuples()
	for f, r := range h.families {
		switch r.phase {
		case Stale:
			// RFC 4724 Section 4.2: "Once the session is re-established,
			// if the "Forwarding State" bit for a specific address family
			// is not set in the newly received Graceful Restart
			// Capability, or if a specific address family is not included
			// in the newly received Graceful Restart Capability, or if the
			// Graceful Restart Capability is not received in the
			// re-established session at all, then the Receiving Speaker
			// MUST immediately remove all the stale routes from the peer
			// that it is retaining for that address family."
			if !gr[f] {
				h.finish(f, r, &a)
			}
		case LLGRStale:
			// RFC 9494 Section 4.2: "Similar to [RFC4724], once the LLGR
			// Period begins, the Helper MUST immediately remove all the
			// stale routes from the peer that it is retaining for that
			// address family if any of the following occur:
			//
			//   *  the F bit for a specific address family is not set in
			//      the newly received LLGR Capability, or
			//
			//   *  a specific address family is not included in the newly
			//      received LLGR Capability, or
			//
			//   *  the LLGR and accompanying GR Capability are not received
			//      in the re-established session at all."
			if t, ok := llgr[f]; !ok || t.Flags&fBit == 0 {
				h.finish(f, r, &a)
			}
		}
	}
	return a
}

// EORReceived is called when the End-of-RIB marker of family f is
// received. RFC 4724 Section 4.2: "Once the End-of-RIB marker for an address
// family is received from the peer, it MUST immediately remove any routes
// from the peer that are still marked as stale for that address family."
func (h *Helper) EORReceived(f bgp.Family) Actions {
	if !h.up {
		panic("gr: EORReceived while the session is not established")
	}
	var a Actions
	if r, ok := h.families[f]; ok {
		h.finish(f, r, &a)
	}
	return a
}

// Abort ends the restart of all families without removing routes. It is
// called when the restart is given up while the peer stays, for example
// when the peer is disabled. The caller removes the routes of the peer.
func (h *Helper) Abort() Actions {
	var a Actions
	h.stopRestartTimer(&a)
	for f, r := range h.families {
		h.untrack(f, r, &a)
	}
	return a
}
