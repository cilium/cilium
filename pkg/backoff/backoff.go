// Copyright 2018-2019 Authors of Cilium
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

package backoff

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rand"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "backoff")

	randGen = rand.NewSafeRand(time.Now().UnixNano())
)

// NodeManager is the interface required to implement cluster size dependent
// intervals
type NodeManager interface {
	ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration
}

// Exponential implements an exponential backoff
type Exponential struct {
	// Min is the minimal backoff time, if unspecified, 1 second will be
	// used
	Min time.Duration

	// Max is the maximum backoff time, if unspecified, no maximum time is
	// applied
	Max time.Duration

	// Factor is the factor the backoff time grows exponentially, if
	// unspecified, a factor of 2.0 will be used
	Factor float64

	// Jitter, when enabled, adds random jitter to the interval
	Jitter bool

	// NodeManager enables the use of cluster size dependent backoff
	// intervals, i.e. the larger the cluster, the longer the backoff
	// interval
	NodeManager NodeManager

	// Name is a free form string describing the operation subject to the
	// backoff, if unspecified, a UUID is generated. This string is used
	// for logging purposes.
	Name string

	attempt int
}

// CalculateDuration calculates the backoff duration based on minimum base
// interval, exponential factor, jitter and number of failures.
func CalculateDuration(min, max time.Duration, factor float64, jitter bool, failures int) time.Duration {
	minFloat := float64(min)
	maxFloat := float64(max)

	t := minFloat * math.Pow(factor, float64(failures))
	if max != time.Duration(0) && t > maxFloat {
		t = maxFloat
	}

	if jitter {
		t = randGen.Float64()*(t-minFloat) + minFloat
	}

	return time.Duration(t)
}

// Wait waits for the required time using an exponential backoff
func (b *Exponential) Wait(ctx context.Context) error {
	b.attempt++
	t := b.Duration(b.attempt)

	log.WithFields(logrus.Fields{
		"time":    t,
		"attempt": b.attempt,
		"name":    b.Name,
	}).Debug("Sleeping with exponential backoff")

	select {
	case <-ctx.Done():
		return fmt.Errorf("exponential backoff cancelled via context: %s", ctx.Err())
	case <-time.After(t):
	}

	return nil
}

// Duration returns the wait duration for the nth attempt
func (b *Exponential) Duration(attempt int) time.Duration {
	if b.Name == "" {
		b.Name = uuid.New().String()
	}

	min := time.Duration(1) * time.Second
	if b.Min != time.Duration(0) {
		min = b.Min
	}

	factor := float64(2)
	if b.Factor != float64(0) {
		factor = b.Factor
	}

	t := CalculateDuration(min, b.Max, factor, b.Jitter, attempt)

	if b.NodeManager != nil {
		t = b.NodeManager.ClusterSizeDependantInterval(t)
	}

	if b.Max != time.Duration(0) && t > b.Max {
		t = b.Max
	}

	return t
}
