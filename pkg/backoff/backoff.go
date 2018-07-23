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

package backoff

import (
	"math"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/uuid"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "backoff")

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

	// Name is a free form string describing the operation subject to the
	// backoff, if unspecified, a UUID is generated. This string is used
	// for logging purposes.
	Name string

	attempt int
}

// Wait waits for the required time using an exponential backoff
func (b *Exponential) Wait() {
	b.attempt++

	if b.Name == "" {
		b.Name = uuid.NewUUID().String()
	}

	min := time.Duration(1) * time.Second
	if b.Min != time.Duration(0) {
		min = b.Min
	}

	factor := float64(2)
	if b.Factor != float64(0) {
		factor = b.Factor
	}

	t := time.Duration(float64(min) * math.Pow(factor, float64(b.attempt)))

	if b.Max != time.Duration(0) && t > b.Max {
		t = b.Max
	}

	log.WithFields(logrus.Fields{
		"time":    t,
		"attempt": b.attempt,
		"name":    b.Name,
	}).Debug("Sleeping with exponential backoff")

	time.Sleep(t)
}
