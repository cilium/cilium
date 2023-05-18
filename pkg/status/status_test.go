// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

type StatusTestSuite struct {
	config Config
	mutex  lock.Mutex
}

var _ = Suite(&StatusTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *StatusTestSuite) SetUpTest(c *C) {
	s.mutex.Lock()
	s.config = Config{
		Interval:         10 * time.Millisecond,
		WarningThreshold: 20 * time.Millisecond,
		FailureThreshold: 80 * time.Millisecond,
	}
	s.mutex.Unlock()
}

func (s *StatusTestSuite) Config() (c Config) {
	s.mutex.Lock()
	c = s.config
	s.mutex.Unlock()
	return
}

func (s *StatusTestSuite) TestVariableProbeInterval(c *C) {
	var runs, ok uint64

	p := []Probe{
		{
			Interval: func(failures int) time.Duration {
				// While failing, retry every millisecond
				if failures > 0 {
					return time.Millisecond
				}

				// Ensure that the regular interval would never retry
				return time.Minute
			},
			Probe: func(ctx context.Context) (interface{}, error) {
				// Let 5 runs fail and then succeed
				atomic.AddUint64(&runs, 1)
				if atomic.LoadUint64(&runs) < 5 {
					return nil, fmt.Errorf("still failing")
				}

				return nil, nil
			},
			OnStatusUpdate: func(status Status) {
				if status.Data == nil && status.Err == nil {
					atomic.AddUint64(&ok, 1)
				}
			},
		},
	}

	collector := NewCollector(p, s.Config())
	defer collector.Close()

	// wait for 5 probe intervals to occur with 1 millisecond interval
	// until we reach success
	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadUint64(&ok) >= 1
	}, 1*time.Second), IsNil)
}

func (s *StatusTestSuite) TestCollectorFailureTimeout(c *C) {
	var ok uint64

	p := []Probe{
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				time.Sleep(s.Config().FailureThreshold * 2)
				return nil, nil
			},
			OnStatusUpdate: func(status Status) {
				if status.StaleWarning && status.Data == nil && status.Err != nil {
					if strings.Contains(status.Err.Error(),
						fmt.Sprintf("within %v seconds", s.Config().FailureThreshold.Seconds())) {

						atomic.AddUint64(&ok, 1)
					}
				}
			},
		},
	}

	collector := NewCollector(p, s.Config())
	defer collector.Close()

	// wait for the failure timeout to kick in
	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadUint64(&ok) >= 1
	}, 1*time.Second), IsNil)
	c.Assert(collector.GetStaleProbes(), HasLen, 1)
}

func (s *StatusTestSuite) TestCollectorSuccess(c *C) {
	var ok, errs uint64
	err := fmt.Errorf("error")

	p := []Probe{
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				if atomic.LoadUint64(&ok) > 3 {
					return nil, err
				}
				return "testData", nil
			},
			OnStatusUpdate: func(status Status) {
				if !errors.Is(status.Err, err) {
					atomic.AddUint64(&errs, 1)
				}
				if !status.StaleWarning && status.Data != nil && status.Err == nil {
					if s, isString := status.Data.(string); isString && s == "testData" {
						atomic.AddUint64(&ok, 1)
					}
				}
			},
		},
	}

	collector := NewCollector(p, s.Config())
	defer collector.Close()

	// wait for the probe to succeed 3 times and to return the error 3 times
	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadUint64(&ok) >= 3 && atomic.LoadUint64(&errs) >= 3
	}, 1*time.Second), IsNil)
	c.Assert(collector.GetStaleProbes(), HasLen, 0)
}

func (s *StatusTestSuite) TestCollectorSuccessAfterTimeout(c *C) {
	var ok, timeout uint64

	p := []Probe{
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				if atomic.LoadUint64(&timeout) == 0 {
					time.Sleep(2 * s.Config().FailureThreshold)
				}
				return nil, nil
			},
			OnStatusUpdate: func(status Status) {
				if status.StaleWarning {
					atomic.AddUint64(&timeout, 1)
				} else {
					atomic.AddUint64(&ok, 1)
				}

			},
		},
	}

	collector := NewCollector(p, s.Config())
	defer collector.Close()

	// wait for the probe to timeout (warning and failure) and then to succeed
	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadUint64(&timeout) == 1 && atomic.LoadUint64(&ok) > 0
	}, 1*time.Second), IsNil)
	c.Assert(collector.GetStaleProbes(), HasLen, 0)
}
