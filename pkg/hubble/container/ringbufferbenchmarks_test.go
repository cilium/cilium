// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// +build !privileged_tests

package container_test

import (
	"testing"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/container"

	"github.com/stretchr/testify/require"
)

// benchmarkCapacity is the capacity used for benchmarks.
const benchmarkCapacity = 4096

type benchmarkRingBufferOptions struct {
	capacity    int
	readers     int
	slowReaders int
}

func BenchmarkRingBufferNoReaders(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{})
}

func BenchmarkRingBufferOneReader(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{
		readers: 1,
	})
}

func BenchmarkRingBufferOneSlowReader(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{
		slowReaders: 1,
	})
}

func BenchmarkRingBufferEightReaders(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{
		readers: 8,
	})
}

func BenchmarkRingBufferEightReadersEightSlowReaders(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{
		readers:     8,
		slowReaders: 8,
	})
}

func BenchmarkRingBufferFiveHundredReaders(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{
		readers: 512,
	})
}

func BenchmarkRingBufferOneThousandReaders(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{
		readers: 1024,
	})
}

func BenchmarkRingBufferOneThousandSlowReaders(b *testing.B) {
	benchmarkRingBuffer(b, benchmarkRingBufferOptions{
		slowReaders: 1024,
	})
}

func benchmarkRingBuffer(b *testing.B, options benchmarkRingBufferOptions) {
	b.ReportAllocs()

	if options.capacity == 0 {
		options.capacity = benchmarkCapacity
	}

	rb := container.NewRingBuffer(
		container.WithCapacity(options.capacity),
	)

	// A reader counts the events it receives over a channel and reports the
	// result over a channel.
	var cancels []container.ReaderCancelFunc
	makeReader := func(resultCh chan<- int, capacity int) {
		ch, cancel := rb.ReadNew(capacity)
		go func() {
			eventsReceived := 0
			for range ch {
				eventsReceived++
			}
			resultCh <- eventsReceived
		}()
		cancels = append(cancels, cancel)
	}

	// readers are created with a channel capacity of b.N ensuring that they
	// can receive all events without blocking.
	readerEventsReceived := make(chan int, options.readers)
	for i := 0; i < options.readers; i++ {
		makeReader(readerEventsReceived, b.N)
	}

	// Slow readers are created with a channel capacity of 0 meaning that they
	// will only receive events if their goroutine is reading from the channel
	// when the event is written.
	slowReaderEventsReceived := make(chan int, options.slowReaders)
	for i := 0; i < options.slowReaders; i++ {
		makeReader(slowReaderEventsReceived, 0)
	}

	event := &v1.Event{}

	b.ResetTimer()

	// Write the same event b.N times.
	for i := 0; i < b.N; i++ {
		rb.Write(event)
	}

	// Cancel all readers.
	for _, cancel := range cancels {
		cancel()
	}

	// Collect results from all readers.
	for i := 0; i < options.readers; i++ {
		require.Equal(b, b.N, <-readerEventsReceived)
	}
	close(readerEventsReceived)
	for i := 0; i < options.slowReaders; i++ {
		require.GreaterOrEqual(b, b.N, <-slowReaderEventsReceived)
	}
	close(slowReaderEventsReceived)
}
