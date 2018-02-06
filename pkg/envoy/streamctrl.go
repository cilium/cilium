package envoy

import (
	"math"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/lock"
)

// StreamControlCtx holds the state of a gRPC stream server instance we need to know about.
type StreamControlCtx struct {
	wg       sync.WaitGroup
	handlers []*StreamControl
}

func (ctx *StreamControlCtx) stop() {
	for _, ctrl := range ctx.handlers {
		ctrl.stopHandling()
	}
	// Wait for everyone to be done.
	ctx.wg.Wait()
}

type versionCompletion struct {
	version    uint64
	msg        string
	completion *completion.Completion // Ack callback interface
}

// StreamControl implements a generic Envoy streamed gRPC API. API
// servers should derive from this and add API-specific functionality
// of their own.
// A 'sync.Cond' is used to signal the stream server goroutine that the current version
// of the resource should be streamed. Envoy stream requests embed a version field that
// is interpreted as a NACK if it repeats the same version as the previous request, and as
// an ACK when it contains the version field from the latest response we sent over.
// 64-bit version numbers are assumed to never wrap around.
type StreamControl struct {
	name                    string
	cond                    sync.Cond // L mutex used to protect members below as well.
	handled                 bool
	ackedVersion            uint64
	sentVersion             uint64
	currentVersion          uint64
	currentVersionNackCount uint
	completions             []versionCompletion
}

// Called with ctrl.cond.L.Lock() held
func (ctrl *StreamControl) addCompletion(wg *completion.WaitGroup, msg string) {
	if wg == nil {
		return
	}

	comp := wg.AddCompletion()

	// Note that we do not start a timer for the timeout, but rely on NACKs to be followed by
	// retries that allows for checking for timeouts at some times in future. This should
	// also work accross Envoy restarts.
	if comp != nil {
		log.Debugf("Envoy: AddCompletion: %s", msg)
		ctrl.completions = append(ctrl.completions,
			versionCompletion{ctrl.currentVersion, msg, comp})
	}
}

// Called with ctrl.cond.L.Lock() held
func (ctrl *StreamControl) handleCompletions(version uint64, success bool) {
	var retained []versionCompletion // No allocation so we can shrink
	for _, comp := range ctrl.completions {
		result := success

		if version >= comp.version {
			// Ack or Nack for this version OR later received
		} else if comp.completion.Context().Err() != nil {
			// Timed out, return failure.
			result = false
		} else {
			retained = append(retained, comp)
			continue
		}

		res := "NACK"
		if result {
			res = "ACK"
		}
		log.Debug("Envoy: ", ctrl.name, " ", comp.msg, " ", res)

		if result {
			comp.completion.Complete()
		}
	}
	ctrl.completions = retained
}

func makeStreamControl(name string) StreamControl {
	return StreamControl{
		name:                    name,
		cond:                    sync.Cond{L: &lock.Mutex{}},
		ackedVersion:            math.MaxUint64,
		sentVersion:             0,
		currentVersion:          1,
		currentVersionNackCount: 0,
	}
}

// update stream control based on received 'version'. Returns true if
// the current version should be sent.
// Lock must be held.
func (ctrl *StreamControl) updateVersionLocked(version uint64) bool {
	// Bump current version UP to sync with the version history of the caller, if we receive
	// evidence for a version we have not sent yet. This can happen when we restart.
	if ctrl.sentVersion < version {
		ctrl.currentVersion = version + 1
		ctrl.currentVersionNackCount = 0
		log.Debug("Envoy: ", ctrl.name, " version bumped to ", ctrl.currentVersion)
	}

	// Roll back acked version if this is a NACK (== version is the same as the
	// previous acked version).
	if version == ctrl.ackedVersion {
		// NACK, bump the nack count and back off if current version is still the same
		if ctrl.currentVersion == ctrl.sentVersion {
			ctrl.currentVersionNackCount++
		}
		// Back the sent version back to the acknowledged version, so anything after it
		// will be re-tried.
		ctrl.sentVersion = version
		log.Debug("Envoy: ", ctrl.name, " NACK received, last acked version is: ", version)
		// Note that we do not trigger an unsuccessful completion, but let that happen
		// at timeout instead.
	} else if version == 0 {
		// Envoy has (re)started, make sure we send the current configuration (again)
		ctrl.sentVersion = version
		log.Debug("Envoy: ", ctrl.name, " detected Envoy (re)start ")
	} else {
		log.Debug("Envoy: ", ctrl.name, " ACK received: ", version)
		ctrl.handleCompletions(version, true)
	}
	ctrl.ackedVersion = version // remember the last acked version

	return ctrl.currentVersion > ctrl.sentVersion
}

func (ctrl *StreamControl) updateVersion(version uint64) bool {
	ctrl.cond.L.Lock()
	defer ctrl.cond.L.Unlock()
	return ctrl.updateVersionLocked(version)
}

// 'handler()' is called to send the current version if it is later than 'version'
// Starts a handler goroutine tracked by 'ctx'.
func (ctrl *StreamControl) startHandler(ctx *StreamControlCtx, handler func() error) {
	ctrl.handled = true
	ctx.handlers = append(ctx.handlers, ctrl)

	ctx.wg.Add(1)
	go func() {
		defer ctx.wg.Done()

		log.Debug("Envoy: Starting stream handler for: ", ctrl.name)

		ctrl.cond.L.Lock()
		for {
			// Quit waiting if we should stop or have something to send.
			// cond.Wait automatically unlocks and locks again.
			for ctrl.handled && ctrl.sentVersion == ctrl.currentVersion {
				ctrl.cond.Wait()
			}
			if !ctrl.handled {
				break // end handling
			}
			// Send the current version
			if handler() == nil {
				ctrl.sentVersion = ctrl.currentVersion
			} else {
				// Sending failed on an error, stop handling
				ctrl.handleCompletions(ctrl.currentVersion, false) // Fail current version
				break
			}
		}
		ctrl.handled = false
		ctrl.cond.L.Unlock()

		log.Debug("Envoy: Stream handler stopped: ", ctrl.name)
	}()
}

// Exponential back-off duration, but capped at one second.
func backoffTime(count uint) time.Duration {
	d := time.Duration(1<<count) * 25 * time.Millisecond
	if d > time.Second {
		return time.Second
	}
	return d
}

// 'version' is the version number of the last successfully received configuration from Envoy,
// 'handler()' is called to send the current version if it is later than 'version'.
// If back off if the current version has already received negative acknowledgements from Envoy
// Starts a handler goroutine on demand tracked by 'ctx'.
func (ctrl *StreamControl) handleVersion(ctx *StreamControlCtx, version uint64, handler func() error) {
	ctrl.cond.L.Lock()
	if ctrl.updateVersionLocked(version) {
		// Have more to send.
		if !ctrl.handled {
			// Start the handler
			ctrl.startHandler(ctx, handler)
		} else {
			// Wake up handler for sending, but delay the signal if need to back off
			// We do an exponential back-off starting at 50ms and doubling by
			if ctrl.currentVersionNackCount > 0 {
				go func(version uint64, d time.Duration) {
					log.Debug("Envoy: ", ctrl.name, " trying version ", version, " again after ", d)
					time.Sleep(d)
					ctrl.cond.L.Lock()
					ctrl.handleCompletions(0, false) // Handle timeouts
					// Signal only if not already stopped and version is still the same.
					// This allows later backoffs to continue undisturbed if need be.
					if ctrl.handled && ctrl.currentVersion == version {
						ctrl.cond.Signal()
					}
					ctrl.cond.L.Unlock()
				}(ctrl.currentVersion, backoffTime(ctrl.currentVersionNackCount))
			} else {
				// No back-off, wake up immediately
				ctrl.cond.Signal()
			}
		}
	}
	ctrl.cond.L.Unlock()
}

func (ctrl *StreamControl) stopHandling() {
	ctrl.cond.L.Lock()
	ctrl.handled = false                          // Tell handler to stop
	ctrl.handleCompletions(math.MaxUint64, false) // Fail remaining completions
	ctrl.cond.Signal()
	ctrl.cond.L.Unlock()
}

// f is called while the lock is held
func (ctrl *StreamControl) bumpVersionFunc(f func()) {
	ctrl.cond.L.Lock()
	ctrl.currentVersion++
	ctrl.currentVersionNackCount = 0
	f()
	ctrl.cond.Signal()
	ctrl.cond.L.Unlock()
}

func (ctrl *StreamControl) bumpVersion() {
	ctrl.cond.L.Lock()
	ctrl.currentVersion++
	ctrl.currentVersionNackCount = 0
	ctrl.cond.Signal()
	ctrl.cond.L.Unlock()
}
