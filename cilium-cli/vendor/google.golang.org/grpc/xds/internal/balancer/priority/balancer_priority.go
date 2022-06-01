/*
 *
 * Copyright 2021 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package priority

import (
	"errors"
	"time"

	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
	"google.golang.org/grpc/connectivity"
)

var (
	// ErrAllPrioritiesRemoved is returned by the picker when there's no priority available.
	ErrAllPrioritiesRemoved = errors.New("no priority is provided, all priorities are removed")
	// DefaultPriorityInitTimeout is the timeout after which if a priority is
	// not READY, the next will be started. It's exported to be overridden by
	// tests.
	DefaultPriorityInitTimeout = 10 * time.Second
)

// syncPriority handles priority after a config update or a child balancer
// connectivity state update. It makes sure the balancer state (started or not)
// is in sync with the priorities (even in tricky cases where a child is moved
// from a priority to another).
//
// It's guaranteed that after this function returns:
// - If some child is READY, it is childInUse, and all lower priorities are
// closed.
// - If some child is newly started(in Connecting for the first time), it is
// childInUse, and all lower priorities are closed.
// - Otherwise, the lowest priority is childInUse (none of the children is
// ready, and the overall state is not ready).
//
// Steps:
// - If all priorities were deleted, unset childInUse (to an empty string), and
// set parent ClientConn to TransientFailure
// - Otherwise, Scan all children from p0, and check balancer stats:
//   - For any of the following cases:
//     - If balancer is not started (not built), this is either a new child with
//       high priority, or a new builder for an existing child.
//     - If balancer is Connecting and has non-nil initTimer (meaning it
//       transitioned from Ready or Idle to connecting, not from TF, so we
//       should give it init-time to connect).
//     - If balancer is READY
//     - If this is the lowest priority
//   - do the following:
//     - if this is not the old childInUse, override picker so old picker is no
//       longer used.
//     - switch to it (because all higher priorities are neither new or Ready)
//     - forward the new addresses and config
//
// Caller must hold b.mu.
func (b *priorityBalancer) syncPriority(forceUpdate bool) {
	// Everything was removed by the update.
	if len(b.priorities) == 0 {
		b.childInUse = ""
		b.priorityInUse = 0
		b.cc.UpdateState(balancer.State{
			ConnectivityState: connectivity.TransientFailure,
			Picker:            base.NewErrPicker(ErrAllPrioritiesRemoved),
		})
		return
	}

	for p, name := range b.priorities {
		child, ok := b.children[name]
		if !ok {
			b.logger.Warningf("child with name %q is not found in children", name)
			continue
		}

		if !child.started ||
			child.state.ConnectivityState == connectivity.Ready ||
			child.state.ConnectivityState == connectivity.Idle ||
			(child.state.ConnectivityState == connectivity.Connecting && child.initTimer != nil) ||
			p == len(b.priorities)-1 {
			if b.childInUse != "" && b.childInUse != child.name {
				// childInUse was set and is different from this child, will
				// change childInUse later. We need to update picker here
				// immediately so parent stops using the old picker.
				b.cc.UpdateState(child.state)
			}
			b.logger.Infof("switching to (%q, %v) in syncPriority", child.name, p)
			oldChildInUse := b.childInUse
			b.switchToChild(child, p)
			if b.childInUse != oldChildInUse || forceUpdate {
				// If child is switched, send the update to the new child.
				//
				// Or if forceUpdate is true (when this is triggered by a
				// ClientConn update), because the ClientConn update might
				// contain changes for this child.
				child.sendUpdate()
			}
			break
		}
	}
}

// Stop priorities [p+1, lowest].
//
// Caller must hold b.mu.
func (b *priorityBalancer) stopSubBalancersLowerThanPriority(p int) {
	for i := p + 1; i < len(b.priorities); i++ {
		name := b.priorities[i]
		child, ok := b.children[name]
		if !ok {
			b.logger.Warningf("child with name %q is not found in children", name)
			continue
		}
		child.stop()
	}
}

// switchToChild does the following:
// - stop all child with lower priorities
// - if childInUse is not this child
//   - set childInUse to this child
//   - if this child is not started, start it
//
// Note that it does NOT send the current child state (picker) to the parent
// ClientConn. The caller needs to send it if necessary.
//
// this can be called when
// 1. first update, start p0
// 2. an update moves a READY child from a lower priority to higher
// 2. a different builder is updated for this child
// 3. a high priority goes Failure, start next
// 4. a high priority init timeout, start next
//
// Caller must hold b.mu.
func (b *priorityBalancer) switchToChild(child *childBalancer, priority int) {
	// Stop lower priorities even if childInUse is same as this child. It's
	// possible this child was moved from a priority to another.
	b.stopSubBalancersLowerThanPriority(priority)

	// If this child is already in use, do nothing.
	//
	// This can happen:
	// - all priorities are not READY, an config update always triggers switch
	// to the lowest. In this case, the lowest child could still be connecting,
	// so we don't stop the init timer.
	// - a high priority is READY, an config update always triggers switch to
	// it.
	if b.childInUse == child.name && child.started {
		return
	}
	b.childInUse = child.name
	b.priorityInUse = priority

	if !child.started {
		child.start()
	}
}

// handleChildStateUpdate start/close priorities based on the connectivity
// state.
func (b *priorityBalancer) handleChildStateUpdate(childName string, s balancer.State) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done.HasFired() {
		return
	}

	priority, ok := b.childToPriority[childName]
	if !ok {
		b.logger.Warningf("priority: received picker update with unknown child %v", childName)
		return
	}

	if b.childInUse == "" {
		b.logger.Warningf("priority: no child is in use when picker update is received")
		return
	}

	// priorityInUse is higher than this priority.
	if b.priorityInUse < priority {
		// Lower priorities should all be closed, this is an unexpected update.
		// Can happen if the child policy sends an update after we tell it to
		// close.
		b.logger.Warningf("priority: received picker update from priority %v,  lower than priority in use %v", priority, b.priorityInUse)
		return
	}

	// Update state in child. The updated picker will be sent to parent later if
	// necessary.
	child, ok := b.children[childName]
	if !ok {
		b.logger.Warningf("priority: child balancer not found for child %v, priority %v", childName, priority)
		return
	}
	oldChildState := child.state
	child.state = s

	// We start/stop the init timer of this child based on the new connectivity
	// state. syncPriority() later will need the init timer (to check if it's
	// nil or not) to decide which child to switch to.
	switch s.ConnectivityState {
	case connectivity.Ready, connectivity.Idle:
		child.reportedTF = false
		child.stopInitTimer()
	case connectivity.TransientFailure:
		child.reportedTF = true
		child.stopInitTimer()
	case connectivity.Connecting:
		if !child.reportedTF {
			child.startInitTimer()
		}
	default:
		// New state is Shutdown, should never happen. Don't forward.
	}

	oldPriorityInUse := b.priorityInUse
	child.parent.syncPriority(false)
	// If child is switched by syncPriority(), it also sends the update from the
	// new child to overwrite the old picker used by the parent.
	//
	// But no update is sent if the child is not switches. That means if this
	// update is from childInUse, and this child is still childInUse after
	// syncing, the update being handled here is not sent to the parent. In that
	// case, we need to do an explicit check here to forward the update.
	if b.priorityInUse == oldPriorityInUse && b.priorityInUse == priority {
		// Special handling for Connecting. If child was not switched, and this
		// is a Connecting->Connecting transition, do not send the redundant
		// update, since all Connecting pickers are the same (they tell the RPCs
		// to repick).
		//
		// This can happen because the initial state of a child (before any
		// update is received) is Connecting. When the child is started, it's
		// picker is sent to the parent by syncPriority (to overwrite the old
		// picker if there's any). When it reports Connecting after being
		// started, it will send a Connecting update (handled here), causing a
		// Connecting->Connecting transition.
		if oldChildState.ConnectivityState == connectivity.Connecting && s.ConnectivityState == connectivity.Connecting {
			return
		}
		// Only forward this update if sync() didn't switch child, and this
		// child is in use.
		//
		// sync() forwards the update if the child was switched, so there's no
		// need to forward again.
		b.cc.UpdateState(child.state)
	}

}
