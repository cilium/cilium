// Copyright 2018 Authors of Cilium
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

package status

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	defaultInterval         = 5 * time.Second
	defaultFailureThreshold = time.Minute
	defaultWarningThreshold = 20 * time.Second
	subsystem               = "status"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)
)

// Status is passed to a probe when its state changes
type Status struct {
	// Data is non-nil when the probe has completed successfully. Data is
	// set to the value returned by Probe()
	Data interface{}

	// Error is non-nil if either the probe file or the Failure or Warning
	// threshold has been reached
	Err error

	// StaleWarning is true once the WarningThreshold has been reached
	StaleWarning bool
}

// Probe is run by the collector at a particular interval between invokations
type Probe struct {
	Name string

	Probe func(ctx context.Context) (interface{}, error)

	// OnStatusUpdate is called whenever the status of the probe changes
	OnStatusUpdate func(status Status)
}

// Collector is a collector of probes used to check status of various subsystems
type Collector struct {
	lock.RWMutex   // protects staleProbes and probeStartTime
	config         Config
	stop           chan struct{}
	staleProbes    map[string]struct{}
	probeStartTime map[string]time.Time
}

// Config is the collector configuration used for a particular collector
type Config struct {
	WarningThreshold time.Duration
	FailureThreshold time.Duration
	Interval         time.Duration
}

// NewCollector creates a collector and starts the given probes.
//
// Each probe runs in a separate goroutine.
func NewCollector(probes []Probe, config Config) *Collector {
	c := &Collector{
		config:         config,
		stop:           make(chan struct{}, 0),
		staleProbes:    make(map[string]struct{}),
		probeStartTime: make(map[string]time.Time),
	}

	if c.config.Interval == time.Duration(0) {
		c.config.Interval = defaultInterval
	}

	if c.config.FailureThreshold == time.Duration(0) {
		c.config.FailureThreshold = defaultFailureThreshold
	}

	if c.config.WarningThreshold == time.Duration(0) {
		c.config.WarningThreshold = defaultWarningThreshold
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
func (c *Collector) GetStaleProbes() map[string]time.Time {
	c.RLock()
	defer c.RUnlock()

	probes := make(map[string]time.Time)

	for p := range c.staleProbes {
		probes[p] = c.probeStartTime[p]
	}

	return probes
}

// spawnProbe continuously calls Probe() and Status(), waiting for the
// defined interval between invocations, until Collector.Close() is called.
// Probe() is called without wait on the when first calling this function.
func (c *Collector) spawnProbe(p *Probe) {
	go func() {
		for {
			c.runProbe(p)

			select {
			case <-c.stop:
				// collector is closed, stop looping
				return
			case <-time.After(c.config.Interval):
				// keep looping
			}
		}
	}()
}

// runProbe runs Probe() once and, on success, Status(). runProbe returns after
// FailureThreshold elapses and calls Status() with no data and an error.  An
// error is included when the probe took longer than WarningThreshold to
// return.
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
	// Do not override start time if the probe is stale
	if _, found := c.staleProbes[p.Name]; !found {
		c.probeStartTime[p.Name] = time.Now()
	}
	c.Unlock()

	go func() {
		statusData, err = p.Probe(ctx)
		close(probeReturned)
	}()

	go func() {
		// Once ctx.Done() has been closed, we notify the polling loop by
		// sending to the ctxTimeout channel. We cannot close the channel, because
		// otherwise the loop will always enter the "<-ctxTimeout" case.
		<-ctx.Done()
		ctxTimeout <- struct{}{}
	}()

	// This is a loop so that, when we hit a FailureThreshold, we still do
	// not return until the probe returns. This is to ensure the same probe
	// does not run again while it is blocked.
	for {
		select {
		case <-c.stop:
			// Collector was closed. The probe will
			// complete in the background and won't be
			// restarted again.
			cancel()
			return

		case <-warningThreshold:
			// Publish warning and continue waiting for probe
			staleErr := fmt.Errorf("No response from %s probe within %v seconds",
				p.Name, c.config.WarningThreshold.Seconds())
			c.updateProbeStatus(p, nil, true, staleErr)

		case <-probeReturned:
			// The probe completed and we can return from runProbe
			switch {
			case hardTimeout:
				// FailureThreshold was already
				// reached. Keep the failure error
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
			staleErr := fmt.Errorf("No response from %s probe within %v seconds",
				p.Name, c.config.FailureThreshold.Seconds())
			c.updateProbeStatus(p, nil, true, staleErr)
			hardTimeout = true
		}
	}
}

func (c *Collector) updateProbeStatus(p *Probe, data interface{}, staleWarning bool, err error) {
	// Update stale status of the probe
	c.Lock()
	startTime := c.probeStartTime[p.Name]
	if staleWarning {
		c.staleProbes[p.Name] = struct{}{}
	} else {
		delete(c.staleProbes, p.Name)
	}
	c.Unlock()

	if staleWarning {
		log.WithField(logfields.StartTime, startTime).
			Warn(fmt.Sprintf("Timeout while waiting for %q probe", p.Name))
	}

	// Notify the probe about status update
	p.OnStatusUpdate(Status{Err: err, Data: data, StaleWarning: staleWarning})
}
