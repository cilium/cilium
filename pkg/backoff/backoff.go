// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package backoff

import (
	"context"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/time"
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

// nodeManager is a wrapper to enable using a plain function as NodeManager to implement
// cluster size dependent intervals
type nodeManager struct {
	clusterSizeDependantInterval func(baseInterval time.Duration) time.Duration
}

// NewNodeManager returns a new NodeManager implementing cluster size dependent intervals
// based on the given function. If the function is nil, then no tuning is performed.
func NewNodeManager(clusterSizeDependantInterval func(baseInterval time.Duration) time.Duration) NodeManager {
	return &nodeManager{clusterSizeDependantInterval: clusterSizeDependantInterval}
}

func (n *nodeManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	if n.clusterSizeDependantInterval == nil {
		return baseInterval
	}

	return n.clusterSizeDependantInterval(baseInterval)
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

	// ResetAfter will reset the exponential back-off if no attempt is made for the amount of time specified here.
	// Needs to be larger than the Max duration, otherwise it will be ignored to avoid accidental resets.
	// If unspecified, no reset is performed.
	ResetAfter time.Duration

	lastBackoffStart time.Time

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

// ClusterSizeDependantInterval returns a time.Duration that is dependent on
// the cluster size, i.e. the number of nodes that have been discovered. This
// can be used to control sync intervals of shared or centralized resources to
// avoid overloading these resources as the cluster grows.
//
// Example sync interval with baseInterval = 1 * time.Minute
//
// nodes | sync interval
// ------+-----------------
// 1     |   41.588830833s
// 2     | 1m05.916737320s
// 4     | 1m36.566274746s
// 8     | 2m11.833474640s
// 16    | 2m49.992800643s
// 32    | 3m29.790453687s
// 64    | 4m10.463236193s
// 128   | 4m51.588744261s
// 256   | 5m32.944565093s
// 512   | 6m14.416550710s
// 1024  | 6m55.946873494s
// 2048  | 7m37.506428894s
// 4096  | 8m19.080616652s
// 8192  | 9m00.662124608s
// 16384 | 9m42.247293667s
func ClusterSizeDependantInterval(baseInterval time.Duration, numNodes int) time.Duration {
	// no nodes are being managed, no work will be performed, return
	// baseInterval to check again in a reasonable timeframe
	if numNodes == 0 {
		return baseInterval
	}

	waitNanoseconds := float64(baseInterval.Nanoseconds()) * math.Log1p(float64(numNodes))
	return time.Duration(int64(waitNanoseconds))
}

// Reset backoff attempt counter
func (b *Exponential) Reset() {
	b.attempt = 0
}

// Wait waits for the required time using an exponential backoff
func (b *Exponential) Wait(ctx context.Context) error {
	if resetDuration := b.ResetAfter; resetDuration != time.Duration(0) && resetDuration > b.Max {
		if !b.lastBackoffStart.IsZero() {
			if time.Since(b.lastBackoffStart) > resetDuration {
				b.Reset()
			}
		}
	}

	b.lastBackoffStart = time.Now()
	b.attempt++
	t := b.Duration(b.attempt)

	log.WithFields(logrus.Fields{
		"time":    t,
		"attempt": b.attempt,
		"name":    b.Name,
	}).Debug("Sleeping with exponential backoff")

	select {
	case <-ctx.Done():
		return fmt.Errorf("exponential backoff cancelled via context: %w", ctx.Err())
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
