// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	// these channels are initialized in startSink and never reassigned, thus
	// they can be accessed without locking mutex
	queue    chan record
	shutdown chan struct{}
	done     chan struct{}
	trigger  chan struct{}
	// mutex protects writes to stats and lastError
	mutex     lock.Mutex
	stats     Statistics
	lastError error
}

// startSink creates a queue and goroutine for the sink. The spawned go
// routine will run until one of the following happens:
//   - sink.stop is called
//   - a p.StopCondition is reached
//   - ctx is cancelled
//   - an error occurred
func startSink(ctx context.Context, p PcapSink, queueSize int) *sink {
	s := &sink{
		queue:     make(chan record, queueSize),
		shutdown:  make(chan struct{}),
		done:      make(chan struct{}),
		trigger:   make(chan struct{}, 1),
		mutex:     lock.Mutex{},
		stats:     Statistics{},
		lastError: nil,
	}

	go func() {
		// this defer executes p.Writer.Close(), but also makes sure to set
		// lastError and close the s.done channel when exiting.
		var err error
		defer func() {
			closeErr := p.Writer.Close()

			s.mutex.Lock()
			if err == nil {
				s.lastError = closeErr
			} else {
				s.lastError = err
			}
			s.mutex.Unlock()
			close(s.done)
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

		for {
			select {
			// s.queue will be closed when the sink is unregistered
			case rec := <-s.queue:
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
			case <-s.shutdown:
				return
			case <-stopAfter:
				// duration of stop condition has been reached
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
	close(s.shutdown)
}

// addToStatistics adds add to the current statistics and returns the resulting
// value.
func (s *sink) addToStatistics(add Statistics) (result Statistics) {
	s.mutex.Lock()
	s.stats.BytesWritten += add.BytesWritten
	s.stats.PacketsWritten += add.PacketsWritten
	s.stats.BytesLost += add.BytesLost
	s.stats.PacketsLost += add.PacketsLost
	result = s.stats
	s.mutex.Unlock()

	// non-blocking send
	select {
	case s.trigger <- struct{}{}:
	default:
	}

	return result
}

// enqueue submits a new record to this sink. If the sink is not keeping up,
// the record is dropped and the sink statistics are updated accordingly
func (s *sink) enqueue(rec record) {
	select {
	case <-s.shutdown:
		// early return if shutting down
		return
	default:
	}

	select {
	case s.queue <- rec:
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
