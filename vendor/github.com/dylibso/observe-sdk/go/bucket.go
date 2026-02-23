package observe

import (
	"log"
	"sync"
	"time"
)

type Flusher interface {
	Flush(events []TraceEvent) error
}

// EventBucket is a bucket for outgoing TraceEvents.
// It only schedules flushes when the bucket goes from empty to 1 item.
// At most the latency to flush the bucket will be flushPeriod.
// It will also flush the TraceEvents in batches according to batch size
type EventBucket struct {
	mu          sync.Mutex
	wg          sync.WaitGroup
	bucket      []TraceEvent
	flushPeriod time.Duration
	batchSize   int
}

// NewEventBucket creates an EventBucket
func NewEventBucket(batchSize int, flushPeriod time.Duration) *EventBucket {
	return &EventBucket{
		flushPeriod: flushPeriod,
		batchSize:   batchSize,
	}
}

// addEvent adds a TraceEvent and schedules to flush to Flusher if needed
func (b *EventBucket) addEvent(e TraceEvent, f Flusher) {
	b.mu.Lock()
	wasEmpty := len(b.bucket) == 0
	b.bucket = append(b.bucket, e)
	b.mu.Unlock()
	// if this is the first event in the bucket,
	// we schedule a flush
	if wasEmpty {
		b.scheduleFlush(f)
	}
}

// Wait will block until all pending flushes are done
func (b *EventBucket) Wait() {
	b.wg.Wait()
}

// scheduleFlush schedules a goroutine to flush
// the bucket at some time in the future depending on flushPeriod.
// Events will continue to build up until the flush comes due
func (b *EventBucket) scheduleFlush(f Flusher) {
	// we start this routine and immediately wait, we are effectively
	// scheduling the flush to run flushPeriod sections later. In the meantime,
	// events may still be coming into the eventBucket
	go func() {
		// register this flush with the wait group
		defer b.wg.Done()
		b.wg.Add(1)

		// wait for flushPeriod
		time.Sleep(b.flushPeriod)

		// move the events out of the EventBucket to a slice
		// and add 1 to the waitgroup
		b.mu.Lock()
		bucket := b.bucket
		b.bucket = nil
		b.mu.Unlock()

		// flush the bucket in chunks of batchSize
		for i := 0; i < len(bucket); i += b.batchSize {
			j := i + b.batchSize
			if j > len(bucket) {
				j = len(bucket)
			}
			// TODO retry logic?
			err := f.Flush(bucket[i:j])
			if err != nil {
				log.Println(err)
			}
		}
	}()
}
