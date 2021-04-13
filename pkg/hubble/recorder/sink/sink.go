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
	"fmt"

	"github.com/cilium/cilium/pkg/hubble/recorder/pcap"
	"github.com/cilium/cilium/pkg/lock"
)

// sink wraps a pcap.RecordWriter by adding a queue and managing its statistics
// regarding written and dropped packets and bytes.
type sink struct {
	mutex   lock.Mutex
	queue   chan record
	done    chan error
	trigger chan struct{}
	stats   Statistics
}

// startSink creates a queue and go routine for the sink. The spawned go
// routine must be stopped via a call to close()
func startSink(ctx context.Context, w pcap.RecordWriter, hdr pcap.Header, queueSize int) *sink {
	s := &sink{
		mutex:   lock.Mutex{},
		queue:   make(chan record, queueSize),
		done:    make(chan error, 1),
		trigger: make(chan struct{}, 1),
		stats:   Statistics{},
	}

	go func() {
		// this defer executes w.Close(), but also makes sure err
		// is sent to the done channel upon exit
		var err error
		defer func() {
			closeErr := w.Close()
			if err == nil {
				err = closeErr
			}
			s.done <- err

			s.mutex.Lock()
			close(s.trigger)
			s.trigger = nil
			s.mutex.Unlock()
		}()

		if err = w.WriteHeader(hdr); err != nil {
			return
		}

		for {
			select {
			// s.queue will be closed when the sink is unregistered
			case rec, ok := <-s.queue:
				if !ok {
					return
				}

				pcapRecord := pcap.Record{
					Timestamp:      rec.timestamp,
					CaptureLength:  rec.inclLen,
					OriginalLength: rec.origLen,
				}

				if err = w.WriteRecord(pcapRecord, rec.data); err != nil {
					return
				}

				s.addToStatistics(Statistics{
					PacketsWritten: 1,
					BytesWritten:   uint64(rec.inclLen),
				})
			case <-ctx.Done():
				err = ctx.Err()
				return
			}
		}
	}()

	return s
}

// close waits for this sink to drain its queue and then closes the underlying
// pcap writer
func (s *sink) close(ctx context.Context) error {
	s.mutex.Lock()
	// closing the queue will cause drain to exit and send back an error (or nil)
	// value in the done channel
	close(s.queue)
	s.queue = nil
	s.mutex.Unlock()

	select {
	case err := <-s.done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for sink to close: %w", ctx.Err())
	}
}

func (s *sink) addToStatistics(add Statistics) {
	s.mutex.Lock()
	s.stats.BytesWritten += add.BytesWritten
	s.stats.PacketsWritten += add.PacketsWritten
	s.stats.BytesLost += add.BytesLost
	s.stats.PacketsLost += add.PacketsLost

	// non-blocking send
	select {
	case s.trigger <- struct{}{}:
	default:
	}

	s.mutex.Unlock()
}

// enqueue submits a new record to this sink. If the sink is not keeping up,
// the record is dropped and the sink statistics are updated accordingly
func (s *sink) enqueue(rec record) {
	s.mutex.Lock()
	// copy queue to avoid concurrent close
	q := s.queue
	if q == nil {
		return
	}
	s.mutex.Unlock()

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
