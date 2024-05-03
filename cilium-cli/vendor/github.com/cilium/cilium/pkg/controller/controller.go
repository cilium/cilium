// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const (
	success = "success"
	failure = "failure"

	// special Group "names" for metrics config
	allControllerMetricsEnabled = "all"
	noControllerMetricsEnabled  = "none"
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

// Group contains metadata about a group of controllers
type Group struct {
	// Name of the controller group.
	//
	// This name MUST NOT be dynamically generated based on
	// resource identifier in order to limit metrics cardinality.
	Name string
}

func NewGroup(name string) Group {
	return Group{Name: name}
}

// ControllerParams contains all parameters of a controller
type ControllerParams struct {
	// Group is used for aggregate metrics collection.
	// The Group.Name must NOT be dynamically generated from a
	// resource identifier in order to limit metrics cardinality.
	Group Group

	Health cell.Health

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

// isGroupMetricEnabled returns true if metrics are enabled for the Group
//
// The controller metrics config option is used to determine
// if "all", "none" (takes precedence over "all"), or the
// given set of Group names should be enabled.
//
// If no controller metrics config option was provided,
// only then is the DefaultMetricsEnabled field used.
func isGroupMetricEnabled(g Group) bool {
	var metricsEnabled = groupMetricEnabled
	if metricsEnabled == nil {
		// There is currently no guarantee that a caller of this function
		// has initialized the configuration map using the hive cell.
		return false
	}

	if metricsEnabled[noControllerMetricsEnabled] {
		// "none" takes precedence over "all"
		return false
	} else if metricsEnabled[allControllerMetricsEnabled] {
		return true
	} else {
		return metricsEnabled[g.Name]
	}
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
type controller struct {
	// Constant after creation, safe to access without locking
	group  Group
	name   string
	uuid   string
	logger *logrus.Entry

	// Channels written to and/or closed by the manager
	stop    chan struct{}
	update  chan ControllerParams
	trigger chan struct{}

	// terminated is closed by the controller goroutine when it terminates
	terminated chan struct{}

	// Manipulated by the controller, read by the Manager, requires locking
	mutex             lock.RWMutex
	successCount      int
	lastSuccessStamp  time.Time
	failureCount      int
	consecutiveErrors int
	lastError         error
	lastErrorStamp    time.Time
	lastDuration      time.Duration
}

// GetSuccessCount returns the number of successful controller runs
func (c *controller) GetSuccessCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.successCount
}

// GetFailureCount returns the number of failed controller runs
func (c *controller) GetFailureCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.failureCount
}

// GetLastError returns the last error returned
func (c *controller) GetLastError() error {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.lastError
}

// GetLastErrorTimestamp returns the last error returned
func (c *controller) GetLastErrorTimestamp() time.Time {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.lastErrorStamp
}

func (c *controller) runController(params ControllerParams) {
	errorRetries := 1

	runTimer, timerDone := inctimer.New()
	defer timerDone()

	for {
		var err error

		interval := params.RunInterval

		start := time.Now()
		err = params.DoFunc(params.Context)
		duration := time.Since(start)

		c.mutex.Lock()
		c.lastDuration = duration
		c.getLogger().Debug("Controller func execution time: ", c.lastDuration)

		if err != nil {
			if params.Context.Err() != nil {
				// The controller's context was canceled. Let's wait for the
				// next controller update (or stop).
				err = NewExitReason("controller context canceled")
			}

			var exitReason ExitReason
			if errors.As(err, &exitReason) {
				// This is actually not an error case, but it causes an exit
				c.recordSuccess(params.Health)
				c.lastError = exitReason // This will be shown in the controller status

				// Don't exit the goroutine, since that only happens when the
				// controller is explicitly stopped. Instead, just wait for
				// the next update.
				c.getLogger().Debug("Controller run succeeded; waiting for next controller update or stop")
				interval = time.Duration(math.MaxInt64)

			} else {
				c.getLogger().WithField(fieldConsecutiveErrors, errorRetries).
					WithError(err).Debug("Controller run failed")
				c.recordError(err, params.Health)

				if !params.NoErrorRetry {
					if params.ErrorRetryBaseDuration != time.Duration(0) {
						interval = time.Duration(errorRetries) * params.ErrorRetryBaseDuration
					} else {
						interval = time.Duration(errorRetries) * time.Second
					}

					if params.MaxRetryInterval > 0 && interval > params.MaxRetryInterval {
						c.getLogger().WithFields(logrus.Fields{
							"calculatedInterval": interval,
							"maxAllowedInterval": params.MaxRetryInterval,
						}).Debug("Cap retry interval to max allowed value")
						interval = params.MaxRetryInterval
					}

					errorRetries++
				}
			}
		} else {
			c.recordSuccess(params.Health)

			// reset error retries after successful attempt
			errorRetries = 1

			// If no run interval is specified, no further updates
			// are required.
			if interval == time.Duration(0) {
				// Don't exit the goroutine, since that only happens when the
				// controller is explicitly stopped. Instead, just wait for
				// the next update.
				c.getLogger().Debug("Controller run succeeded; waiting for next controller update or stop")
				interval = time.Duration(math.MaxInt64)
			}
		}

		c.mutex.Unlock()

		select {
		case <-c.stop:
			goto shutdown

		case params = <-c.update:
			// update channel is never closed
		case <-runTimer.After(interval):
			// timer channel is not yet closed
		case <-c.trigger:
			// trigger channel is never closed
		}

		// If we receive a signal on multiple channels golang will pick one randomly.
		// This select will make sure we don't execute the controller
		// while we are shutting down.
		select {
		case <-c.stop:
			goto shutdown
		default:
		}
	}

shutdown:
	c.getLogger().Debug("Shutting down controller")

	if err := params.StopFunc(context.TODO()); err != nil {
		c.mutex.Lock()
		c.recordError(err, params.Health)
		c.mutex.Unlock()
		c.getLogger().WithField(fieldConsecutiveErrors, errorRetries).
			WithError(err).Warn("Error on Controller stop")
	}

	close(c.terminated)
}

// logger returns a logrus object with controllerName and UUID fields.
func (c *controller) getLogger() *logrus.Entry {
	if c.logger == nil {
		c.logger = log.WithFields(logrus.Fields{
			fieldControllerName: c.name,
			fieldUUID:           c.uuid,
		})
	}

	return c.logger
}

// recordError updates all statistic collection variables on error
// c.mutex must be held.
func (c *controller) recordError(err error, h cell.Health) {
	if h != nil {
		h.Degraded(c.name, err)
	}
	c.lastError = err
	c.lastErrorStamp = time.Now()
	c.failureCount++
	c.consecutiveErrors++

	metrics.ControllerRuns.WithLabelValues(failure).Inc()
	if isGroupMetricEnabled(c.group) {
		GroupRuns.WithLabelValues(c.group.Name, failure).Inc()
	}
	metrics.ControllerRunsDuration.WithLabelValues(failure).Observe(c.lastDuration.Seconds())
}

// recordSuccess updates all statistic collection variables on success
// c.mutex must be held.
func (c *controller) recordSuccess(h cell.Health) {
	if h != nil {
		h.OK(c.name)
	}

	c.lastError = nil
	c.lastSuccessStamp = time.Now()
	c.successCount++
	c.consecutiveErrors = 0

	metrics.ControllerRuns.WithLabelValues(success).Inc()
	if isGroupMetricEnabled(c.group) {
		GroupRuns.WithLabelValues(c.group.Name, success).Inc()
	}
	metrics.ControllerRunsDuration.WithLabelValues(success).Observe(c.lastDuration.Seconds())
}
