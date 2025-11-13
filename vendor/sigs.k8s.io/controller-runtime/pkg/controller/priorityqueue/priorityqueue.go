package priorityqueue

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/btree"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/internal/metrics"
)

// AddOpts describes the options for adding items to the queue.
type AddOpts struct {
	After       time.Duration
	RateLimited bool
	// Priority is the priority of the item. Higher values
	// indicate higher priority.
	// Defaults to zero if unset.
	Priority *int
}

// PriorityQueue is a priority queue for a controller. It
// internally de-duplicates all items that are added to
// it. It will use the max of the passed priorities and the
// min of possible durations.
type PriorityQueue[T comparable] interface {
	workqueue.TypedRateLimitingInterface[T]
	AddWithOpts(o AddOpts, Items ...T)
	GetWithPriority() (item T, priority int, shutdown bool)
}

// Opts contains the options for a PriorityQueue.
type Opts[T comparable] struct {
	// Ratelimiter is being used when AddRateLimited is called. Defaults to a per-item exponential backoff
	// limiter with an initial delay of five milliseconds and a max delay of 1000 seconds.
	RateLimiter    workqueue.TypedRateLimiter[T]
	MetricProvider workqueue.MetricsProvider
	Log            logr.Logger
}

// Opt allows to configure a PriorityQueue.
type Opt[T comparable] func(*Opts[T])

// New constructs a new PriorityQueue.
func New[T comparable](name string, o ...Opt[T]) PriorityQueue[T] {
	opts := &Opts[T]{}
	for _, f := range o {
		f(opts)
	}

	if opts.RateLimiter == nil {
		opts.RateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[T](5*time.Millisecond, 1000*time.Second)
	}

	if opts.MetricProvider == nil {
		opts.MetricProvider = metrics.WorkqueueMetricsProvider{}
	}

	pq := &priorityqueue[T]{
		log:         opts.Log,
		items:       map[T]*item[T]{},
		queue:       btree.NewG(32, less[T]),
		becameReady: sets.Set[T]{},
		metrics:     newQueueMetrics[T](opts.MetricProvider, name, clock.RealClock{}),
		// itemOrWaiterAdded indicates that an item or
		// waiter was added. It must be buffered, because
		// if we currently process items we can't tell
		// if that included the new item/waiter.
		itemOrWaiterAdded: make(chan struct{}, 1),
		rateLimiter:       opts.RateLimiter,
		locked:            sets.Set[T]{},
		done:              make(chan struct{}),
		get:               make(chan item[T]),
		now:               time.Now,
		tick:              time.Tick,
	}

	go pq.spin()
	go pq.logState()
	if _, ok := pq.metrics.(noMetrics[T]); !ok {
		go pq.updateUnfinishedWorkLoop()
	}

	return pq
}

type priorityqueue[T comparable] struct {
	log logr.Logger
	// lock has to be acquired for any access any of items, queue, addedCounter
	// or becameReady
	lock  sync.Mutex
	items map[T]*item[T]
	queue bTree[*item[T]]

	// addedCounter is a counter of elements added, we need it
	// because unixNano is not guaranteed to be unique.
	addedCounter uint64

	// becameReady holds items that are in the queue, were added
	// with non-zero after and became ready. We need it to call the
	// metrics add exactly once for them.
	becameReady sets.Set[T]
	metrics     queueMetrics[T]

	itemOrWaiterAdded chan struct{}

	rateLimiter workqueue.TypedRateLimiter[T]

	// locked contains the keys we handed out through Get() and that haven't
	// yet been returned through Done().
	locked     sets.Set[T]
	lockedLock sync.RWMutex

	shutdown atomic.Bool
	done     chan struct{}

	get chan item[T]

	// waiters is the number of routines blocked in Get, we use it to determine
	// if we can push items. Every manipulation has to be protected with the lock.
	waiters int64

	// Configurable for testing
	now  func() time.Time
	tick func(time.Duration) <-chan time.Time
}

func (w *priorityqueue[T]) AddWithOpts(o AddOpts, items ...T) {
	if w.shutdown.Load() {
		return
	}

	w.lock.Lock()
	defer w.lock.Unlock()

	for _, key := range items {
		after := o.After
		if o.RateLimited {
			rlAfter := w.rateLimiter.When(key)
			if after == 0 || rlAfter < after {
				after = rlAfter
			}
		}

		var readyAt *time.Time
		if after > 0 {
			readyAt = ptr.To(w.now().Add(after))
			w.metrics.retry()
		}
		if _, ok := w.items[key]; !ok {
			item := &item[T]{
				Key:          key,
				AddedCounter: w.addedCounter,
				Priority:     ptr.Deref(o.Priority, 0),
				ReadyAt:      readyAt,
			}
			w.items[key] = item
			w.queue.ReplaceOrInsert(item)
			if item.ReadyAt == nil {
				w.metrics.add(key, item.Priority)
			}
			w.addedCounter++
			continue
		}

		// The b-tree de-duplicates based on ordering and any change here
		// will affect the order - Just delete and re-add.
		item, _ := w.queue.Delete(w.items[key])
		if newPriority := ptr.Deref(o.Priority, 0); newPriority > item.Priority {
			// Update depth metric only if the item in the queue was already added to the depth metric.
			if item.ReadyAt == nil || w.becameReady.Has(key) {
				w.metrics.updateDepthWithPriorityMetric(item.Priority, newPriority)
			}
			item.Priority = newPriority
		}

		if item.ReadyAt != nil && (readyAt == nil || readyAt.Before(*item.ReadyAt)) {
			if readyAt == nil && !w.becameReady.Has(key) {
				w.metrics.add(key, item.Priority)
			}
			item.ReadyAt = readyAt
		}

		w.queue.ReplaceOrInsert(item)
	}

	if len(items) > 0 {
		w.notifyItemOrWaiterAdded()
	}
}

func (w *priorityqueue[T]) notifyItemOrWaiterAdded() {
	select {
	case w.itemOrWaiterAdded <- struct{}{}:
	default:
	}
}

func (w *priorityqueue[T]) spin() {
	blockForever := make(chan time.Time)
	var nextReady <-chan time.Time
	nextReady = blockForever
	var nextItemReadyAt time.Time

	for {
		select {
		case <-w.done:
			return
		case <-w.itemOrWaiterAdded:
		case <-nextReady:
			nextReady = blockForever
			nextItemReadyAt = time.Time{}
		}

		func() {
			w.lock.Lock()
			defer w.lock.Unlock()

			w.lockedLock.Lock()
			defer w.lockedLock.Unlock()

			// manipulating the tree from within Ascend might lead to panics, so
			// track what we want to delete and do it after we are done ascending.
			var toDelete []*item[T]

			var key T

			// Items in the queue tree are sorted first by priority and second by readiness, so
			// items with a lower priority might be ready further down in the queue.
			// We iterate through the priorities high to low until we find a ready item
			pivot := item[T]{
				Key:          key,
				AddedCounter: 0,
				Priority:     math.MaxInt,
				ReadyAt:      nil,
			}

			for {
				pivotChange := false

				w.queue.AscendGreaterOrEqual(&pivot, func(item *item[T]) bool {
					// Item is locked, we can not hand it out
					if w.locked.Has(item.Key) {
						return true
					}

					if item.ReadyAt != nil {
						if readyAt := item.ReadyAt.Sub(w.now()); readyAt > 0 {
							if nextItemReadyAt.After(*item.ReadyAt) || nextItemReadyAt.IsZero() {
								nextReady = w.tick(readyAt)
								nextItemReadyAt = *item.ReadyAt
							}

							// Adjusting the pivot item moves the ascend to the next lower priority
							pivot.Priority = item.Priority - 1
							pivotChange = true
							return false
						}
						if !w.becameReady.Has(item.Key) {
							w.metrics.add(item.Key, item.Priority)
							w.becameReady.Insert(item.Key)
						}
					}

					if w.waiters == 0 {
						// Have to keep iterating here to ensure we update metrics
						// for further items that became ready and set nextReady.
						return true
					}

					w.metrics.get(item.Key, item.Priority)
					w.locked.Insert(item.Key)
					w.waiters--
					delete(w.items, item.Key)
					toDelete = append(toDelete, item)
					w.becameReady.Delete(item.Key)
					w.get <- *item

					return true
				})

				if !pivotChange {
					break
				}
			}

			for _, item := range toDelete {
				w.queue.Delete(item)
			}
		}()
	}
}

func (w *priorityqueue[T]) Add(item T) {
	w.AddWithOpts(AddOpts{}, item)
}

func (w *priorityqueue[T]) AddAfter(item T, after time.Duration) {
	w.AddWithOpts(AddOpts{After: after}, item)
}

func (w *priorityqueue[T]) AddRateLimited(item T) {
	w.AddWithOpts(AddOpts{RateLimited: true}, item)
}

func (w *priorityqueue[T]) GetWithPriority() (_ T, priority int, shutdown bool) {
	if w.shutdown.Load() {
		var zero T
		return zero, 0, true
	}

	w.lock.Lock()
	w.waiters++
	w.lock.Unlock()

	w.notifyItemOrWaiterAdded()

	select {
	case <-w.done:
		// Return if the queue was shutdown while we were already waiting for an item here.
		// For example controller workers are continuously calling GetWithPriority and
		// GetWithPriority is blocking the workers if there are no items in the queue.
		// If the controller and accordingly the queue is then shut down, without this code
		// branch the controller workers remain blocked here and are unable to shut down.
		var zero T
		return zero, 0, true
	case item := <-w.get:
		return item.Key, item.Priority, w.shutdown.Load()
	}
}

func (w *priorityqueue[T]) Get() (item T, shutdown bool) {
	key, _, shutdown := w.GetWithPriority()
	return key, shutdown
}

func (w *priorityqueue[T]) Forget(item T) {
	w.rateLimiter.Forget(item)
}

func (w *priorityqueue[T]) NumRequeues(item T) int {
	return w.rateLimiter.NumRequeues(item)
}

func (w *priorityqueue[T]) ShuttingDown() bool {
	return w.shutdown.Load()
}

func (w *priorityqueue[T]) Done(item T) {
	w.lockedLock.Lock()
	defer w.lockedLock.Unlock()
	w.locked.Delete(item)
	w.metrics.done(item)
	w.notifyItemOrWaiterAdded()
}

func (w *priorityqueue[T]) ShutDown() {
	w.shutdown.Store(true)
	close(w.done)
}

// ShutDownWithDrain just calls ShutDown, as the draining
// functionality is not used by controller-runtime.
func (w *priorityqueue[T]) ShutDownWithDrain() {
	w.ShutDown()
}

// Len returns the number of items that are ready to be
// picked up. It does not include items that are not yet
// ready.
func (w *priorityqueue[T]) Len() int {
	w.lock.Lock()
	defer w.lock.Unlock()

	var result int
	w.queue.Ascend(func(item *item[T]) bool {
		if item.ReadyAt == nil || item.ReadyAt.Compare(w.now()) <= 0 {
			result++
			return true
		}
		return false
	})

	return result
}

func (w *priorityqueue[T]) logState() {
	t := time.Tick(10 * time.Second)
	for {
		select {
		case <-w.done:
			return
		case <-t:
		}

		// Log level may change at runtime, so keep the
		// loop going even if a given level is currently
		// not enabled.
		if !w.log.V(5).Enabled() {
			continue
		}
		w.lock.Lock()
		items := make([]*item[T], 0, len(w.items))
		w.queue.Ascend(func(item *item[T]) bool {
			items = append(items, item)
			return true
		})
		w.lock.Unlock()

		w.log.V(5).Info("workqueue_items", "items", items)
	}
}

func less[T comparable](a, b *item[T]) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.ReadyAt == nil && b.ReadyAt != nil {
		return true
	}
	if b.ReadyAt == nil && a.ReadyAt != nil {
		return false
	}
	if a.ReadyAt != nil && b.ReadyAt != nil && !a.ReadyAt.Equal(*b.ReadyAt) {
		return a.ReadyAt.Before(*b.ReadyAt)
	}

	return a.AddedCounter < b.AddedCounter
}

type item[T comparable] struct {
	Key          T          `json:"key"`
	AddedCounter uint64     `json:"addedCounter"`
	Priority     int        `json:"priority"`
	ReadyAt      *time.Time `json:"readyAt,omitempty"`
}

func (w *priorityqueue[T]) updateUnfinishedWorkLoop() {
	t := time.Tick(500 * time.Millisecond) // borrowed from workqueue: https://github.com/kubernetes/kubernetes/blob/67a807bf142c7a2a5ecfdb2a5d24b4cdea4cc79c/staging/src/k8s.io/client-go/util/workqueue/queue.go#L182
	for {
		select {
		case <-w.done:
			return
		case <-t:
		}
		w.metrics.updateUnfinishedWork()
	}
}

type bTree[T any] interface {
	ReplaceOrInsert(item T) (_ T, _ bool)
	Delete(item T) (T, bool)
	Ascend(iterator btree.ItemIteratorG[T])
	AscendGreaterOrEqual(pivot T, iterator btree.ItemIteratorG[T])
}
