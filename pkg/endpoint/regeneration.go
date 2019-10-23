// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// RegenerateAfterCreation handles the first regeneration of an endpoint after
// it is created.
// After a call to `Regenerate` on the endpoint is made, `endpointStartFunc`
// is invoked - this can be used as a callback to expose the endpoint to other
// subsystems if needed.
// If syncBuild is true, this function waits for specific conditions until
// returning:
// * if the endpoint has a sidecar proxy, it waits for the endpoint's BPF
// program to be generated for the first time.
// * otherwise, waits for the endpoint to complete its first full regeneration.
func (e *Endpoint) RegenerateAfterCreation(ctx context.Context, endpointStartFunc func(), syncBuild bool) error {
	if err := e.lockAlive(); err != nil {
		return fmt.Errorf("endpoint was deleted while processing the request")
	}

	build := e.getState() == StateReady
	if build {
		e.setState(StateWaitingToRegenerate, "Identity is known at endpoint creation time")
	}
	e.unlock()

	if build {
		// Do not synchronously regenerate the endpoint when first creating it.
		// We have custom logic later for waiting for specific checkpoints to be
		// reached upon regeneration later (checking for when BPF programs have
		// been compiled), as opposed to waiting for the entire regeneration to
		// be complete (including proxies being configured). This is done to
		// avoid a chicken-and-egg problem with L7 policies are imported which
		// select the endpoint being generated, as when such policies are
		// imported, regeneration blocks on waiting for proxies to be
		// configured. When Cilium is used with Istio, though, the proxy is
		// started as a sidecar, and is not launched yet when this specific code
		// is executed; if we waited for regeneration to be complete, including
		// proxy configuration, this code would effectively deadlock addition
		// of endpoints.
		e.Regenerate(&regeneration.ExternalRegenerationMetadata{
			Reason:        "Initial build on endpoint creation",
			ParentContext: ctx,
		})
	}

	if endpointStartFunc != nil {
		endpointStartFunc()
	}

	// Wait for endpoint to be in "ready" state if specified in API call.
	if !syncBuild {
		return nil
	}

	return e.waitForFirstRegeneration(ctx)
}

func (e *Endpoint) waitForFirstRegeneration(ctx context.Context) error {
	e.getLogger().Info("Waiting for endpoint to be generated")

	// Default timeout for PUT /endpoint/{id} is 60 seconds, so put timeout
	// in this function a bit below that timeout. If the timeout for clients
	// in API is below this value, they will get a message containing
	// "context deadline exceeded" if the operation takes longer than the
	// client's configured timeout value.
	ctx, cancel := context.WithTimeout(ctx, EndpointGenerationTimeout)

	// Check the endpoint's state and labels periodically.
	ticker := time.NewTicker(1 * time.Second)
	defer func() {
		cancel()
		ticker.Stop()
	}()

	// Wait for any successful BPF regeneration, which is indicated by any
	// positive policy revision (>0). As long as at least one BPF
	// regeneration is successful, the endpoint has network connectivity
	// so we can return from the creation API call.
	revCh := e.WaitForPolicyRevision(ctx, 1, nil)

	for {
		select {
		case <-revCh:
			if ctx.Err() == nil {
				// At least one BPF regeneration has successfully completed.
				return nil
			}

		case <-ctx.Done():
		case <-ticker.C:
			if err := e.rlockAlive(); err != nil {
				return fmt.Errorf("endpoint was deleted while waiting for initial endpoint generation to complete")
			}
			hasSidecarProxy := e.HasSidecarProxy()
			e.runlock()
			if hasSidecarProxy && e.bpfProgramInstalled() {
				// If the endpoint is determined to have a sidecar proxy,
				// return immediately to let the sidecar container start,
				// in case it is required to enforce L7 rules.
				e.getLogger().Info("Endpoint has sidecar proxy, returning from synchronous creation request before regeneration has succeeded")
				return nil
			}
		}

		if ctx.Err() != nil {
			return fmt.Errorf("timeout while waiting for initial endpoint generation to complete")
		}
	}
}

// RegenerateWait should only be called when endpoint's state has successfully
// been changed to "waiting-to-regenerate"
func (e *Endpoint) RegenerateWait(reason string) error {
	if !<-e.Regenerate(&regeneration.ExternalRegenerationMetadata{Reason: reason}) {
		return fmt.Errorf("error while regenerating endpoint."+
			" For more info run: 'cilium endpoint get %d'", e.ID)
	}
	return nil
}

// Called with e.Mutex UNlocked
func (e *Endpoint) regenerate(context *regenerationContext) (retErr error) {
	var revision uint64
	var compilationExecuted bool
	var err error

	context.Stats = regenerationStatistics{}
	stats := &context.Stats
	stats.totalTime.Start()
	e.getLogger().WithFields(logrus.Fields{
		logfields.StartTime: time.Now(),
		logfields.Reason:    context.Reason,
	}).Debug("Regenerating endpoint")

	defer func() {
		// This has to be within a func(), not deferred directly, so that the
		// value of retErr is passed in from when regenerate returns.
		e.updateRegenerationStatistics(context, retErr)
	}()

	e.buildMutex.Lock()
	defer e.buildMutex.Unlock()

	stats.waitingForLock.Start()
	// Check if endpoints is still alive before doing any build
	err = e.lockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return err
	}

	// When building the initial drop policy in waiting-for-identity state
	// the state remains unchanged
	//
	// GH-5350: Remove this special case to require checking for StateWaitingForIdentity
	if e.getState() != StateWaitingForIdentity &&
		!e.BuilderSetStateLocked(StateRegenerating, "Regenerating endpoint: "+context.Reason) {
		e.getLogger().WithField(logfields.EndpointState, e.state).Debug("Skipping build due to invalid state")
		e.unlock()

		return fmt.Errorf("Skipping build due to invalid state: %s", e.state)
	}

	e.unlock()

	stats.prepareBuild.Start()
	origDir := e.StateDirectoryPath()
	context.datapathRegenerationContext.currentDir = origDir

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := e.NextDirectoryPath()
	context.datapathRegenerationContext.nextDir = tmpDir

	// Remove an eventual existing temporary directory that has been left
	// over to make sure we can start the build from scratch
	if err := e.removeDirectory(tmpDir); err != nil && !os.IsNotExist(err) {
		stats.prepareBuild.End(false)
		return fmt.Errorf("unable to remove old temporary directory: %s", err)
	}

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		stats.prepareBuild.End(false)
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	stats.prepareBuild.End(true)

	defer func() {
		if err := e.lockAlive(); err != nil {
			if retErr == nil {
				retErr = err
			} else {
				e.logDisconnectedMutexAction(err, "after regenerate")
			}
			return
		}

		// Guarntee removal of temporary directory regardless of outcome of
		// build. If the build was successful, the temporary directory will
		// have been moved to a new permanent location. If the build failed,
		// the temporary directory will still exist and we will reomve it.
		e.removeDirectory(tmpDir)

		// Set to Ready, but only if no other changes are pending.
		// State will remain as waiting-to-regenerate if further
		// changes are needed. There should be an another regenerate
		// queued for taking care of it.
		e.BuilderSetStateLocked(StateReady, "Completed endpoint regeneration with no pending regeneration requests")
		e.unlock()
	}()

	revision, compilationExecuted, err = e.regenerateBPF(context)
	if err != nil {
		failDir := e.FailedDirectoryPath()
		e.getLogger().WithFields(logrus.Fields{
			logfields.Path: failDir,
		}).Warn("generating BPF for endpoint failed, keeping stale directory.")

		// Remove an eventual existing previous failure directory
		e.removeDirectory(failDir)
		os.Rename(tmpDir, failDir)
		return err
	}

	return e.updateRealizedState(stats, origDir, revision, compilationExecuted)
}

func (e *Endpoint) updateRegenerationStatistics(context *regenerationContext, err error) {
	success := err == nil
	stats := &context.Stats

	stats.totalTime.End(success)
	stats.success = success

	e.mutex.RLock()
	stats.endpointID = e.ID
	stats.policyStatus = e.policyStatus()
	e.runlock()
	stats.SendMetrics()

	fields := logrus.Fields{
		logfields.Reason: context.Reason,
	}
	for field, stat := range stats.GetMap() {
		fields[field] = stat.Total()
	}
	for field, stat := range stats.datapathRealization.GetMap() {
		fields[field] = stat.Total()
	}
	scopedLog := e.getLogger().WithFields(fields)

	if err != nil {
		scopedLog.WithError(err).Warn("Regeneration of endpoint failed")
		e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
		return
	}

	scopedLog.Debug("Completed endpoint regeneration")
	e.LogStatusOK(BPF, "Successfully regenerated endpoint program (Reason: "+context.Reason+")")
}

// RegenerateIfAlive queue a regeneration of this endpoint into the build queue
// of the endpoint and returns a channel that is closed when the regeneration of
// the endpoint is complete. The channel returns:
//  - false if the regeneration failed
//  - true if the regeneration succeed
//  - nothing and the channel is closed if the regeneration did not happen
func (e *Endpoint) RegenerateIfAlive(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
	if err := e.lockAlive(); err != nil {
		log.WithError(err).Warnf("Endpoint disappeared while queued to be regenerated: %s", regenMetadata.Reason)
		e.LogStatus(Policy, Failure, "Error while handling policy updates for endpoint: "+err.Error())
	} else {
		var regen bool
		state := e.getState()
		switch state {
		case StateRestoring, StateWaitingToRegenerate:
			e.setState(state, fmt.Sprintf("Skipped duplicate endpoint regeneration trigger due to %s", regenMetadata.Reason))
			regen = false
		default:
			regen = e.setState(StateWaitingToRegenerate, fmt.Sprintf("Triggering endpoint regeneration due to %s", regenMetadata.Reason))
		}
		e.unlock()
		if regen {
			// Regenerate logs status according to the build success/failure
			return e.Regenerate(regenMetadata)
		}
	}

	ch := make(chan bool)
	close(ch)
	return ch
}

// Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state == StateWaitingToRegenerate or with
// e.state == StateWaitingForIdentity
func (e *Endpoint) Regenerate(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
	done := make(chan bool, 1)

	var (
		ctx   context.Context
		cFunc context.CancelFunc
	)

	if regenMetadata.ParentContext != nil {
		ctx, cFunc = context.WithCancel(regenMetadata.ParentContext)
	} else {
		ctx, cFunc = context.WithCancel(e.aliveCtx)
	}

	regenContext := ParseExternalRegenerationMetadata(ctx, cFunc, regenMetadata)

	epEvent := eventqueue.NewEvent(&EndpointRegenerationEvent{
		regenContext: regenContext,
		ep:           e,
	})

	// This may block if the Endpoint's EventQueue is full. This has to be done
	// synchronously as some callers depend on the fact that the event is
	// synchronously enqueued.
	resChan, err := e.eventQueue.Enqueue(epEvent)
	if err != nil {
		e.getLogger().Errorf("enqueue of EndpointRegenerationEvent failed: %s", err)
		done <- false
		close(done)
		return done
	}

	go func() {

		// Free up resources with context.
		defer cFunc()

		var (
			buildSuccess bool
			regenError   error
			canceled     bool
		)

		select {
		case result, ok := <-resChan:
			if ok {
				regenResult := result.(*EndpointRegenerationResult)
				regenError = regenResult.err
				buildSuccess = regenError == nil

				if regenError != nil {
					e.getLogger().WithError(regenError).Error("endpoint regeneration failed")
				}
			} else {
				// This may be unnecessary(?) since 'closing' of the results
				// channel means that event has been cancelled?
				e.getLogger().Debug("regeneration was cancelled")
				canceled = true
			}
		}

		// If a build is canceled, that means that the Endpoint is being deleted
		// not that the build failed.
		if !buildSuccess && !canceled {
			select {
			case e.regenFailedChan <- struct{}{}:
			default:
				// If we can't write to the channel, that means that it is
				// full / a regeneration will occur - we don't have to
				// do anything.
			}
		}
		done <- buildSuccess
		close(done)
	}()

	return done
}

var reasonRegenRetry = "retrying regeneration"

// startRegenerationFailureHandler waits for a build of the Endpoint to fail.
// Terminates when the given Endpoint is deleted.
// If a build fails, the controller tries to regenerate the
// Endpoint until it succeeds. Once the controller succeeds, it will not be
// ran again unless another build failure occurs. If the call to `Regenerate`
// fails inside of the controller,
func (e *Endpoint) startRegenerationFailureHandler() {
	e.controllers.UpdateController(fmt.Sprintf("endpoint-%s-regeneration-recovery", e.StringID()), controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			select {
			case <-e.regenFailedChan:
				e.getLogger().Debug("received signal that regeneration failed")
			case <-ctx.Done():
				e.getLogger().Debug("exiting retrying regeneration goroutine due to endpoint being deleted")
				return nil
			}

			if err := e.lockAlive(); err != nil {
				// We don't need to regenerate because the endpoint is d
				// disconnecting / is disconnected, exit gracefully.
				return nil
			}

			stateTransitionSucceeded := e.setState(StateWaitingToRegenerate, reasonRegenRetry)
			e.unlock()
			if !stateTransitionSucceeded {
				// Another regeneration has already been enqueued.
				return nil
			}

			r := &regeneration.ExternalRegenerationMetadata{
				// TODO (ianvernon) - is there a way we can plumb a parent
				// context to a controller (e.g., endpoint.aliveCtx)?
				ParentContext: ctx,
				Reason:        reasonRegenRetry,
				// Completely rewrite the endpoint - we don't know the nature
				// of the failure, simply that something failed.
				RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
			}
			if success := <-e.Regenerate(r); success {
				return nil
			}
			return fmt.Errorf("regeneration recovery failed")
		},
		ErrorRetryBaseDuration: 2 * time.Second,
	})
}

func (e *Endpoint) notifyEndpointRegeneration(err error) {
	repr, reprerr := monitorAPI.EndpointRegenRepr(e, err)
	if reprerr != nil {
		e.getLogger().WithError(reprerr).Warn("Notifying monitor about endpoint regeneration failed")
	}

	if err != nil {
		if reprerr == nil && !option.Config.DryMode {
			e.owner.SendNotification(monitorAPI.AgentNotifyEndpointRegenerateFail, repr)
		}
	} else {
		if reprerr == nil && !option.Config.DryMode {
			e.owner.SendNotification(monitorAPI.AgentNotifyEndpointRegenerateSuccess, repr)
		}
	}
}
