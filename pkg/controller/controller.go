// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const (
	success = "success"
	failure = "failure"
)

// ControllerFunc is a function that the controller runs. This type is used for
// DoFunc and StopFunc.
type ControllerFunc func(ctx context.Context) error

// ExitReason is a returnable type from DoFunc that causes the
// controller to exit. This reason is recorded in the controller's status. The
// controller is not removed from any manager.
// Construct one with NewExitReason("a reason")
type ExitReason struct {
	// This is constucted in this odd way because the type assertion in
	// runController didn't work otherwise.
	error
}

// NewExitReason returns a new ExitReason
func NewExitReason(reason string) ExitReason {
	return ExitReason{errors.New(reason)}
}

// ControllerParams contains all parameters of a controller
type ControllerParams struct {
	// DoFunc is the function that will be run until it succeeds and/or
	// using the interval RunInterval if not 0.
	// An unset DoFunc is an error and will be logged as one.
	DoFunc ControllerFunc

	// CancelDoFuncOnUpdate when set to true cancels the controller context
	// (the DoFunc) to allow quick termination of controller
	CancelDoFuncOnUpdate bool

	// StopFunc is called when the controller stops. It is intended to run any
	// clean-up tasks for the controller (e.g. deallocate/release resources)
	// It is guaranteed that DoFunc is called at least once before StopFunc is
	// called.
	// An unset StopFunc is not an error (and will be a no-op)
	// Note: Since this occurs on controller exit, error counts and tracking may
	// not be checked after StopFunc is run.
	StopFunc ControllerFunc

	// If set to any other value than 0, will cause DoFunc to be run in the
	// specified interval. The interval starts from when the DoFunc has
	// returned last
	RunInterval time.Duration

	// If set to any other value than 0, will cap the error retry interval
	// to the specified interval.
	MaxRetryInterval time.Duration

	// ErrorRetryBaseDuration is the initial time to wait to run DoFunc
	// again on return of an error. On each consecutive error, this value
	// is multiplied by the number of consecutive errors to provide a
	// constant back off. The default is 1s.
	ErrorRetryBaseDuration time.Duration

	// NoErrorRetry when set to true, disabled retries on errors
	NoErrorRetry bool

	Context context.Context
}

// undefinedDoFunc is used when no DoFunc is set. controller.DoFunc is set to this
// when the controller is incorrectly initialised.
func undefinedDoFunc(name string) error {
	return fmt.Errorf("controller %s DoFunc is nil", name)
}

// NoopFunc is a no-op placeholder for DoFunc & StopFunc.
// It is automatically used when StopFunc is undefined, and can be used as a
// DoFunc stub when the controller should only run StopFunc.
func NoopFunc(ctx context.Context) error {
	return nil
}

// Controller is a simple pattern that allows to perform the following
// tasks:
//   - Run an operation in the background and retry until it succeeds
//   - Perform a regular sync operation in the background
//
// A controller has configurable retry intervals and will collect statistics
// on number of successful runs, number of failures, last error message,
// and last error timestamp.
//
// Controllers have a name and are tied to a Manager. The manager is typically
// bound to higher level objects such as endpoint. These higher level objects
// can then run multiple controllers to perform async tasks such as:
//   - Annotating k8s resources with values
//   - Synchronizing an object with the kvstore
//   - Any other async operation to may fail and require retries
//
// Embedding the Manager into higher level resources allows to bind controllers
// to the lifetime of that object. Controllers also have a UUID to allow
// correlating all log messages of a controller instance.
//
// Guidelines to writing controllers:
//   - Make sure that the task the controller performs is done in an atomic
//     fashion, e.g. if a controller modifies a resource in multiple steps, an
//     intermediate manipulation operation failing should not leave behind
//     an inconsistent state. This can typically be achieved by locking the
//     resource and rolling back or by using transactions.
//   - Controllers typically act on behalf of a higher level object such as an
//     endpoint. The controller must ensure that the higher level object is
//     properly locked when accessing any fields.
//   - Controllers run asynchronously in the background, it is the responsibility
//     of the controller to be aware of the lifecycle of the owning higher level
//     object. This is typically achieved by removing all controllers when the
//     owner dies. It is the responsibility of the owner to either lock the owner
//     in a way that will delay destruction throughout the controller run or to
//     check for the destruction throughout the run.
type Controller struct {
	mutex             lock.RWMutex
	name              string
	params            ControllerParams
	successCount      int
	lastSuccessStamp  time.Time
	failureCount      int
	consecutiveErrors int
	lastError         error
	lastErrorStamp    time.Time
	lastDuration      time.Duration
	uuid              string
	stop              chan struct{}
	update            chan struct{}
	trigger           chan struct{}
	ctxDoFunc         context.Context
	cancelDoFunc      context.CancelFunc

	// terminated is closed after the controller has been terminated
	terminated chan struct{}
}

// GetSuccessCount returns the number of successful controller runs
func (c *Controller) GetSuccessCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.successCount
}

// GetFailureCount returns the number of failed controller runs
func (c *Controller) GetFailureCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.failureCount
}

// GetLastError returns the last error returned
func (c *Controller) GetLastError() error {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.lastError
}

// Trigger triggers the controller
func (c *Controller) Trigger() {
	select {
	case c.trigger <- struct{}{}:
	default:
	}
}

// GetLastErrorTimestamp returns the last error returned
func (c *Controller) GetLastErrorTimestamp() time.Time {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.lastErrorStamp
}

func (c *Controller) runController() {
	errorRetries := 1

	c.mutex.RLock()
	ctx := c.ctxDoFunc
	params := c.params
	c.mutex.RUnlock()
	runFunc := true
	interval := 10 * time.Minute
	maxRetryInterval := params.MaxRetryInterval
	runTimer, timerDone := inctimer.New()
	defer timerDone()

	for {
		var err error
		if runFunc {
			interval = params.RunInterval

			start := time.Now()
			err = params.DoFunc(ctx)
			duration := time.Since(start)

			c.mutex.Lock()
			c.lastDuration = duration
			c.getLogger().Debug("Controller func execution time: ", c.lastDuration)

			if err != nil {
				if ctx.Err() != nil {
					// The controller's context was canceled. Let's wait for the
					// next controller update (or stop).
					err = NewExitReason("controller context canceled")
				}

				switch err := err.(type) {
				case ExitReason:
					// This is actually not an error case, but it causes an exit
					c.recordSuccess()
					c.lastError = err // This will be shown in the controller status

					// Don't exit the goroutine, since that only happens when the
					// controller is explicitly stopped. Instead, just wait for
					// the next update.
					c.getLogger().Debug("Controller run succeeded; waiting for next controller update or stop")
					runFunc = false
					interval = 10 * time.Minute

				default:
					c.getLogger().WithField(fieldConsecutiveErrors, errorRetries).
						WithError(err).Debug("Controller run failed")
					c.recordError(err)

					if !params.NoErrorRetry {
						if params.ErrorRetryBaseDuration != time.Duration(0) {
							interval = time.Duration(errorRetries) * params.ErrorRetryBaseDuration
						} else {
							interval = time.Duration(errorRetries) * time.Second
						}

						if maxRetryInterval > 0 && interval > maxRetryInterval {
							c.getLogger().WithFields(logrus.Fields{
								"calculatedInterval": interval,
								"maxAllowedInterval": maxRetryInterval,
							}).Debug("Cap retry interval to max allowed value")
							interval = maxRetryInterval
						}

						errorRetries++
					}
				}
			} else {
				c.recordSuccess()

				// reset error retries after successful attempt
				errorRetries = 1

				// If no run interval is specified, no further updates
				// are required.
				if interval == time.Duration(0) {
					// Don't exit the goroutine, since that only happens when the
					// controller is explicitly stopped. Instead, just wait for
					// the next update.
					c.getLogger().Debug("Controller run succeeded; waiting for next controller update or stop")
					runFunc = false
					interval = 10 * time.Minute
				}
			}

			c.mutex.Unlock()
		}
		select {
		case <-c.stop:
			goto shutdown

		case <-c.update:
			// If we receive a signal on both channels c.stop and c.update,
			// golang will pick either c.stop or c.update randomly.
			// This select will make sure we don't execute the controller
			// while we are shutting down.
			select {
			case <-c.stop:
				goto shutdown
			default:
			}
			// Pick up any changes to the parameters in case the controller has
			// been updated.
			c.mutex.RLock()
			ctx = c.ctxDoFunc
			params = c.params
			c.mutex.RUnlock()
			runFunc = true

		case <-runTimer.After(interval):
		case <-c.trigger:
			runFunc = true
		}

	}

shutdown:
	c.getLogger().Debug("Shutting down controller")

	if err := params.StopFunc(context.TODO()); err != nil {
		c.mutex.Lock()
		c.recordError(err)
		c.mutex.Unlock()
		c.getLogger().WithField(fieldConsecutiveErrors, errorRetries).
			WithError(err).Warn("Error on Controller stop")
	}

	close(c.terminated)
}

// updateParamsLocked sets the specified controller's parameters.
//
// If the RunInterval exceeds ControllerMaxInterval, it will be capped.
func (c *Controller) updateParamsLocked(params ControllerParams) {
	if c.params.CancelDoFuncOnUpdate && c.cancelDoFunc != nil {
		c.cancelDoFunc()

		// (re)set the context as the previous might have been cancelled
		if params.Context == nil {
			c.ctxDoFunc, c.cancelDoFunc = context.WithCancel(context.Background())
		} else {
			c.ctxDoFunc, c.cancelDoFunc = context.WithCancel(params.Context)
		}
	}

	c.params = params

	maxInterval := time.Duration(option.Config.MaxControllerInterval) * time.Second
	if maxInterval > 0 && params.RunInterval > maxInterval {
		c.getLogger().Infof("Limiting interval to %s", maxInterval)
		c.params.RunInterval = maxInterval
	}
}

func (c *Controller) stopController() {
	if c.cancelDoFunc != nil {
		c.cancelDoFunc()
	}

	close(c.stop)
	close(c.update)
}

// logger returns a logrus object with controllerName and UUID fields.
func (c *Controller) getLogger() *logrus.Entry {
	return log.WithFields(logrus.Fields{
		fieldControllerName: c.name,
		fieldUUID:           c.uuid,
	})
}

// GetStatusModel returns a models.ControllerStatus representing the
// controller's configuration & status
func (c *Controller) GetStatusModel() *models.ControllerStatus {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	status := &models.ControllerStatus{
		Name: c.name,
		UUID: strfmt.UUID(c.uuid),
		Configuration: &models.ControllerStatusConfiguration{
			ErrorRetry:     !c.params.NoErrorRetry,
			ErrorRetryBase: strfmt.Duration(c.params.ErrorRetryBaseDuration),
			Interval:       strfmt.Duration(c.params.RunInterval),
		},
		Status: &models.ControllerStatusStatus{
			SuccessCount:            int64(c.successCount),
			LastSuccessTimestamp:    strfmt.DateTime(c.lastSuccessStamp),
			FailureCount:            int64(c.failureCount),
			LastFailureTimestamp:    strfmt.DateTime(c.lastErrorStamp),
			ConsecutiveFailureCount: int64(c.consecutiveErrors),
		},
	}

	if c.lastError != nil {
		status.Status.LastFailureMsg = c.lastError.Error()
	}

	return status
}

// recordError updates all statistic collection variables on error
// c.mutex must be held.
func (c *Controller) recordError(err error) {
	c.lastError = err
	c.lastErrorStamp = time.Now()
	c.failureCount++
	c.consecutiveErrors++
	metrics.ControllerRuns.WithLabelValues(failure).Inc()
	metrics.ControllerRunsDuration.WithLabelValues(failure).Observe(c.lastDuration.Seconds())
}

// recordSuccess updates all statistic collection variables on success
// c.mutex must be held.
func (c *Controller) recordSuccess() {
	c.lastError = nil
	c.lastSuccessStamp = time.Now()
	c.successCount++
	c.consecutiveErrors = 0

	metrics.ControllerRuns.WithLabelValues(success).Inc()
	metrics.ControllerRunsDuration.WithLabelValues(success).Observe(c.lastDuration.Seconds())
}
