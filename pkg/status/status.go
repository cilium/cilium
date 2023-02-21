// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"runtime/pprof"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	subsystem = "status"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)
)

// Status is passed to a probe when its state changes
type Status struct {
	// Data is non-nil when the probe has completed successfully. Data is
	// set to the value returned by Probe()
	Data interface{}

	// Err is non-nil if either the probe file or the Failure or Warning
	// threshold has been reached
	Err error

	// StaleWarning is true once the WarningThreshold has been reached
	StaleWarning bool
}

// Probe is run by the collector at a particular interval between invocations
type Probe struct {
	Name string

	Probe func(ctx context.Context) (interface{}, error)

	// OnStatusUpdate is called whenever the status of the probe changes
	OnStatusUpdate func(status Status)

	// Interval allows to specify a probe specific interval that can be
	// mutated based on whether the probe is failing or based on external
	// factors such as current cluster size
	Interval func(failures int) time.Duration

	// consecutiveFailures is the number of consecutive failures in the
	// probe becoming stale or failing. It is managed by
	// updateProbeStatus()
	consecutiveFailures int
}

// Collector concurrently runs probes used to check status of various subsystems
type Collector struct {
	lock.RWMutex   // protects staleProbes and probeStartTime
	config         Config
	stop           chan struct{}
	staleProbes    map[string]struct{}
	probeStartTime map[string]time.Time

	// lastStackdumpTime is the last time we dumped stack; only do it
	// every 5 minutes so we don't waste resources.
	lastStackdumpTime atomic.Int64
}

// Config is the collector configuration
type Config struct {
	WarningThreshold time.Duration
	FailureThreshold time.Duration
	Interval         time.Duration
	StackdumpPath    string
}

// NewCollector creates a collector and starts the given probes.
//
// Each probe runs in a separate goroutine.
func NewCollector(probes []Probe, config Config) *Collector {
	c := &Collector{
		config:         config,
		stop:           make(chan struct{}),
		staleProbes:    make(map[string]struct{}),
		probeStartTime: make(map[string]time.Time),
	}

	if c.config.Interval == time.Duration(0) {
		c.config.Interval = defaults.StatusCollectorInterval
	}

	if c.config.FailureThreshold == time.Duration(0) {
		c.config.FailureThreshold = defaults.StatusCollectorFailureThreshold
	}

	if c.config.WarningThreshold == time.Duration(0) {
		c.config.WarningThreshold = defaults.StatusCollectorWarningThreshold
	}

	for i := range probes {
		c.spawnProbe(&probes[i])
	}

	return c
}

// Close exits all probes and shuts down the collector
// TODO(brb): call it when daemon exits (after GH#6248).
func (c *Collector) Close() {
	close(c.stop)
}

// GetStaleProbes returns a map of stale probes which key is a probe name and
// value is a time when the last instance of the probe has been started.
//
// A probe is declared stale if it hasn't returned in FailureThreshold.
func (c *Collector) GetStaleProbes() map[string]time.Time {
	c.RLock()
	defer c.RUnlock()

	probes := make(map[string]time.Time, len(c.staleProbes))

	for p := range c.staleProbes {
		probes[p] = c.probeStartTime[p]
	}

	return probes
}

// spawnProbe starts a goroutine which invokes the probe at the particular interval.
func (c *Collector) spawnProbe(p *Probe) {
	go func() {
		timer, stopTimer := inctimer.New()
		defer stopTimer()
		for {
			c.runProbe(p)

			interval := c.config.Interval
			if p.Interval != nil {
				interval = p.Interval(p.consecutiveFailures)
			}
			select {
			case <-c.stop:
				// collector is closed, stop looping
				return
			case <-timer.After(interval):
				// keep looping
			}
		}
	}()
}

// runProbe runs the given probe, and returns either after the probe has returned
// or after the collector has been closed.
func (c *Collector) runProbe(p *Probe) {
	var (
		statusData       interface{}
		err              error
		warningThreshold = time.After(c.config.WarningThreshold)
		hardTimeout      = false
		probeReturned    = make(chan struct{}, 1)
		ctx, cancel      = context.WithTimeout(context.Background(), c.config.FailureThreshold)
		ctxTimeout       = make(chan struct{}, 1)
	)

	c.Lock()
	c.probeStartTime[p.Name] = time.Now()
	c.Unlock()

	go func() {
		statusData, err = p.Probe(ctx)
		close(probeReturned)
	}()

	go func() {
		// Once ctx.Done() has been closed, we notify the polling loop by
		// sending to the ctxTimeout channel. We cannot just close the channel,
		// because otherwise the loop will always enter the "<-ctxTimeout" case.
		<-ctx.Done()
		ctxTimeout <- struct{}{}
	}()

	// This is a loop so that, when we hit a FailureThreshold, we still do
	// not return until the probe returns. This is to ensure the same probe
	// does not run again while it is blocked.
	for {
		select {
		case <-c.stop:
			// Collector was closed. The probe will complete in the background
			// and won't be restarted again.
			cancel()
			return

		case <-warningThreshold:
			// Just warn and continue waiting for probe
			log.WithField(logfields.Probe, p.Name).
				Warnf("No response from probe within %v seconds",
					c.config.WarningThreshold.Seconds())

		case <-probeReturned:
			// The probe completed and we can return from runProbe
			switch {
			case hardTimeout:
				// FailureThreshold was already reached. Keep the failure error
				// message
			case err != nil:
				c.updateProbeStatus(p, nil, false, err)
			default:
				c.updateProbeStatus(p, statusData, false, nil)
			}

			cancel()
			return

		case <-ctxTimeout:
			// We have timed out. Report a status and mark that we timed out so we
			// do not emit status later.
			staleErr := fmt.Errorf("no response from %s probe within %v seconds",
				p.Name, c.config.FailureThreshold.Seconds())
			c.updateProbeStatus(p, nil, true, staleErr)
			hardTimeout = true
		}
	}
}

func (c *Collector) updateProbeStatus(p *Probe, data interface{}, stale bool, err error) {
	// Update stale status of the probe
	c.Lock()
	startTime := c.probeStartTime[p.Name]
	if stale {
		c.staleProbes[p.Name] = struct{}{}
		p.consecutiveFailures++
	} else {
		delete(c.staleProbes, p.Name)
		if err == nil {
			p.consecutiveFailures = 0
		} else {
			p.consecutiveFailures++
		}
	}
	c.Unlock()

	if stale {
		log.WithFields(logrus.Fields{
			logfields.StartTime: startTime,
			logfields.Probe:     p.Name,
		}).Warn("Timeout while waiting probe")

		// We just had a probe time out. This is commonly caused by a deadlock.
		// So, capture a stack dump to aid in debugging.
		go c.maybeDumpStack()
	}

	// Notify the probe about status update
	p.OnStatusUpdate(Status{Err: err, Data: data, StaleWarning: stale})
}

// maybeDumpStack dumps the goroutine stack to a file on disk (usually in /run/cilium/state)
// if one hasn't been written in the past 5 minutes.
// This is triggered if a collector is stale, which can be caused by deadlocks.
func (c *Collector) maybeDumpStack() {
	if c.config.StackdumpPath == "" {
		return
	}

	now := time.Now().Unix()
	before := c.lastStackdumpTime.Load()
	if now-before < 5*60 {
		return
	}
	swapped := c.lastStackdumpTime.CompareAndSwap(before, now)
	if !swapped {
		return
	}

	profile := pprof.Lookup("goroutine")
	if profile == nil {
		return
	}

	out, err := os.Create(c.config.StackdumpPath)
	if err != nil {
		log.WithError(err).WithField("path", c.config.StackdumpPath).Warn("Failed to write stack dump")
	}
	defer out.Close()
	gzout := gzip.NewWriter(out)
	defer gzout.Close()

	profile.WriteTo(gzout, 2) // 2: print same stack format as panic
	log.Infof("Wrote stack dump to %s", c.config.StackdumpPath)
}
