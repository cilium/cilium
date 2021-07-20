// Copyright 2021 Authors of Cilium
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

package sink

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/hubble/recorder/pcap"
	"github.com/cilium/cilium/pkg/lock"
)

// sink wraps a pcap.RecordWriter by adding a queue and managing its statistics
// regarding written and dropped packets and bytes.
type sink struct {
	mutex     lock.Mutex
	queue     chan record
	done      chan struct{}
	trigger   chan struct{}
	stats     Statistics
	lastError error
}

// startSink creates a queue and go routine for the sink. The spawned go
// routine will run until one of the following happens:
//  - sink.stop is called
//  - a p.StopCondition is reached
//  - ctx is cancelled
//  - an error occurred
func startSink(ctx context.Context, p PcapSink, queueSize int) *sink {
	s := &sink{
		mutex:     lock.Mutex{},
		queue:     make(chan record, queueSize),
		done:      make(chan struct{}),
		trigger:   make(chan struct{}, 1),
		stats:     Statistics{},
		lastError: nil,
	}

	go func() {
		// this defer executes w.Close(), but also makes sure set lastError and
		// close the channels when exiting.
		var err error
		defer func() {
			closeErr := p.Writer.Close()

			s.mutex.Lock()
			if err == nil {
				s.lastError = closeErr
			} else {
				s.lastError = err
			}
			close(s.done)
			s.mutex.Unlock()
		}()

		stop := p.StopCondition
		var stopAfter <-chan time.Time
		if stop.DurationElapsed != 0 {
			stopTimer := time.NewTimer(stop.DurationElapsed)
			defer func() {
				stopTimer.Stop()
			}()
			stopAfter = stopTimer.C
		}

		if err = p.Writer.WriteHeader(p.Header); err != nil {
			return
		}

		s.mutex.Lock()
		queue := s.queue
		s.mutex.Unlock()

		for {
			select {
			// queue will be closed when the sink is unregistered
			case rec, ok := <-queue:
				if !ok {
					return
				}

				pcapRecord := pcap.Record{
					Timestamp:      rec.timestamp,
					CaptureLength:  rec.inclLen,
					OriginalLength: rec.origLen,
				}

				if err = p.Writer.WriteRecord(pcapRecord, rec.data); err != nil {
					return
				}

				stats := s.addToStatistics(Statistics{
					PacketsWritten: 1,
					BytesWritten:   uint64(rec.inclLen),
				})
				if (stop.PacketsCaptured > 0 && stats.PacketsWritten >= stop.PacketsCaptured) ||
					(stop.BytesCaptured > 0 && stats.BytesWritten >= stop.BytesCaptured) {
					return
				}
			case <-stopAfter:
				// duration for stop condition has been reached
				return
			case <-ctx.Done():
				err = ctx.Err()
				return
			}
		}
	}()

	return s
}

// stop requests the sink to stop recording
func (s *sink) stop() {
	s.mutex.Lock()
	// closing the queue will cause the `startSink` method to drain the queue,
	// and then send back a signal by closing the s.done channel
	close(s.queue)
	s.queue = nil
	s.mutex.Unlock()
}

// addToStatistics adds add to the current statistics and returns the resulting
// value.
func (s *sink) addToStatistics(add Statistics) (result Statistics) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.stats.BytesWritten += add.BytesWritten
	s.stats.PacketsWritten += add.PacketsWritten
	s.stats.BytesLost += add.BytesLost
	s.stats.PacketsLost += add.PacketsLost

	// non-blocking send
	select {
	case s.trigger <- struct{}{}:
	default:
	}

	return s.stats
}

// enqueue submits a new record to this sink. If the sink is not keeping up,
// the record is dropped and the sink statistics are updated accordingly
func (s *sink) enqueue(rec record) {
	s.mutex.Lock()
	// copy queue to avoid concurrent close
	q := s.queue
	s.mutex.Unlock()

	// already stopped
	if q == nil {
		return
	}

	select {
	case q <- rec:
		// successfully enqueued rec in sink
		return
	default:
	}

	// sink queue was full, update statistics
	s.addToStatistics(Statistics{
		PacketsLost: 1,
		BytesLost:   uint64(rec.inclLen),
	})
}

// copyStats creates a snapshot of the current statistics
func (s *sink) copyStats() Statistics {
	s.mutex.Lock()
	stats := s.stats
	s.mutex.Unlock()

	return stats
}

// err returns the last error which occurred in the sink.
// This will always return nil before sink.done has signalled.
func (s *sink) err() error {
	s.mutex.Lock()
	err := s.lastError
	s.mutex.Unlock()

	return err
}
