package priorityqueue

import (
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
//
// When an item that is already enqueued at a lower priority
// is re-enqueued with a higher priority, it will be placed at
// the end among items of the new priority, in order to
// preserve FIFO semantics within each priority level.
// The effective duration (i.e. the ready time) is still
// computed as the minimum across all enqueues.
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

type bufferItem[T comparable] struct {
	opts  AddOpts
	items []T
}

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
		log:                  opts.Log,
		itemAddedToAddBuffer: make(chan struct{}, 1),
		items:                map[T]*item[T]{},
		ready:                btree.NewG(32, lessReady[T]),
		waiting:              btree.NewG(32, lessWaiting[T]),
		metrics:              newQueueMetrics[T](opts.MetricProvider, name, clock.RealClock{}),
		// readyItemOrWaiterAdded indicates that a ready item or
		// waiter was added. It must be buffered, because
		// if we currently process items we can't tell
		// if that included the new item/waiter.
		readyItemOrWaiterAdded:    make(chan struct{}, 1),
		waitingItemAddedOrUpdated: make(chan struct{}, 1),
		rateLimiter:               opts.RateLimiter,
		locked:                    sets.Set[T]{},
		done:                      make(chan struct{}),
		get:                       make(chan item[T]),
		now:                       time.Now,
		tick:                      time.Tick,
	}

	go pq.handleAddBuffer()
	go pq.handleReadyItems()
	go pq.handleWaitingItems()
	go pq.logState()
	if _, ok := pq.metrics.(noMetrics[T]); !ok {
		go pq.updateUnfinishedWorkLoop()
	}

	return pq
}

type priorityqueue[T comparable] struct {
	log logr.Logger

	addBufferLock        sync.Mutex
	addBuffer            []bufferItem[T]
	itemAddedToAddBuffer chan struct{}

	// lock has to be acquired for any access to any of items, ready, waiting,
	// addedCounter or waiters.
	lock    sync.Mutex
	items   map[T]*item[T]
	ready   bTree[*item[T]]
	waiting bTree[*item[T]]

	// addedCounter is a counter of elements added, we need it
	// to provide FIFO semantics.
	addedCounter uint64

	metrics queueMetrics[T]

	readyItemOrWaiterAdded    chan struct{}
	waitingItemAddedOrUpdated chan struct{}

	rateLimiter workqueue.TypedRateLimiter[T]

	// locked contains the keys we handed out through Get() and that haven't
	// yet been returned through Done().
	locked     sets.Set[T]
	lockedLock sync.Mutex

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

	if len(items) == 0 {
		return
	}

	w.addBufferLock.Lock()
	w.addBuffer = append(w.addBuffer, bufferItem[T]{
		opts:  o,
		items: items,
	})
	w.addBufferLock.Unlock()

	w.notifyItemAddedToAddBuffer()
}

func (w *priorityqueue[T]) handleAddBuffer() {
	for {
		select {
		case <-w.done:
			return
		case <-w.itemAddedToAddBuffer:
		}

		w.lock.Lock()
		w.lockedFlushAddBuffer()
		w.lock.Unlock()
	}
}

func (w *priorityqueue[T]) lockedFlushAddBuffer() {
	w.addBufferLock.Lock()
	buffer := w.addBuffer
	w.addBuffer = make([]bufferItem[T], 0, len(buffer))
	w.addBufferLock.Unlock()

	for _, v := range buffer {
		w.lockedAddWithOpts(v.opts, v.items...)
	}
}

func (w *priorityqueue[T]) lockedAddWithOpts(o AddOpts, items ...T) {
	if w.shutdown.Load() {
		return
	}

	var readyItemAdded bool
	var waitingItemAddedOrUpdated bool

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
			w.addedCounter++
			w.items[key] = item
			if readyAt != nil {
				w.waiting.ReplaceOrInsert(item)
				waitingItemAddedOrUpdated = true
			} else {
				w.ready.ReplaceOrInsert(item)
				w.metrics.add(key, item.Priority)
				readyItemAdded = true
			}
			continue
		}

		if w.items[key].ReadyAt == nil {
			readyAt = nil
		} else if readyAt != nil && w.items[key].ReadyAt.Before(*readyAt) {
			readyAt = w.items[key].ReadyAt
		}

		priority := w.items[key].Priority
		addedCounter := w.items[key].AddedCounter
		if newPriority := ptr.Deref(o.Priority, 0); newPriority > w.items[key].Priority {
			// Update depth metric only if the item was already ready
			if w.items[key].ReadyAt == nil {
				w.metrics.updateDepthWithPriorityMetric(w.items[key].Priority, newPriority)
			}
			priority = newPriority
			addedCounter = w.addedCounter
			w.addedCounter++
		}

		var tree, previousTree bTree[*item[T]]
		switch {
		case readyAt == nil && w.items[key].ReadyAt == nil:
			tree, previousTree = w.ready, w.ready
		case readyAt == nil && w.items[key].ReadyAt != nil:
			tree, previousTree = w.ready, w.waiting
			readyItemAdded = true
			w.metrics.add(key, priority)
		case readyAt != nil:
			// We are in the update path and we set readyAt to nil if the
			// existing item has a nil readyAt, so we can be sure here that
			// it has a non-nil readyAt/is in w.waiting.
			tree, previousTree = w.waiting, w.waiting
			waitingItemAddedOrUpdated = true
		}

		item, _ := previousTree.Delete(w.items[key])
		item.ReadyAt = readyAt
		item.Priority = priority
		item.AddedCounter = addedCounter
		tree.ReplaceOrInsert(item)
	}

	if readyItemAdded {
		w.notifyReadyItemOrWaiterAdded()
	}
	if waitingItemAddedOrUpdated {
		w.notifyWaitingItemAddedOrUpdated()
	}
}

func (w *priorityqueue[T]) notifyItemAddedToAddBuffer() {
	select {
	case w.itemAddedToAddBuffer <- struct{}{}:
	default:
	}
}

func (w *priorityqueue[T]) notifyReadyItemOrWaiterAdded() {
	select {
	case w.readyItemOrWaiterAdded <- struct{}{}:
	default:
	}
}

func (w *priorityqueue[T]) notifyWaitingItemAddedOrUpdated() {
	select {
	case w.waitingItemAddedOrUpdated <- struct{}{}:
	default:
	}
}

func (w *priorityqueue[T]) handleWaitingItems() {
	blockForever := make(chan time.Time)
	var nextReady <-chan time.Time
	nextReady = blockForever

	for {
		select {
		case <-w.done:
			return
		case <-w.waitingItemAddedOrUpdated:
		case <-nextReady:
			nextReady = blockForever
		}

		func() {
			w.lock.Lock()
			defer w.lock.Unlock()

			var toMove []*item[T]
			w.waiting.Ascend(func(item *item[T]) bool {
				readyIn := item.ReadyAt.Sub(w.now()) // Store this to prevent TOCTOU issues
				if readyIn <= 0 {
					toMove = append(toMove, item)
					return true
				}

				nextReady = w.tick(readyIn)
				return false
			})

			// Don't manipulate the tree from within Ascend
			for _, toMove := range toMove {
				w.waiting.Delete(toMove)
				toMove.ReadyAt = nil

				// Bump added counter so items get sorted by when
				// they became ready, not when they were added.
				toMove.AddedCounter = w.addedCounter
				w.addedCounter++

				w.metrics.add(toMove.Key, toMove.Priority)
				w.ready.ReplaceOrInsert(toMove)
			}

			if len(toMove) > 0 {
				w.notifyReadyItemOrWaiterAdded()
			}
		}()
	}
}

func (w *priorityqueue[T]) handleReadyItems() {
	for {
		select {
		case <-w.done:
			return
		case <-w.readyItemOrWaiterAdded:
		}

		func() {
			w.lock.Lock()
			defer w.lock.Unlock()

			// Flush is performed before reading items to avoid errors caused by asynchronous behavior,
			// primarily for unit testing purposes.
			// Successfully adding a ready item may result in an additional call to handleReadyItems(),
			// but the cost is negligible.
			w.lockedFlushAddBuffer()

			if w.waiters == 0 {
				return
			}

			w.lockedLock.Lock()
			defer w.lockedLock.Unlock()

			// manipulating the tree from within Ascend might lead to panics, so
			// track what we want to delete and do it after we are done ascending.
			var toDelete []*item[T]

			w.ready.Ascend(func(item *item[T]) bool {
				// Item is locked, we can not hand it out
				if w.locked.Has(item.Key) {
					return true
				}

				w.metrics.get(item.Key, item.Priority)
				w.locked.Insert(item.Key)
				w.waiters--
				delete(w.items, item.Key)
				toDelete = append(toDelete, item)
				w.get <- *item

				return w.waiters > 0
			})

			for _, item := range toDelete {
				w.ready.Delete(item)
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

	w.notifyReadyItemOrWaiterAdded()

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
	w.notifyReadyItemOrWaiterAdded()
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

	// Flush is performed before reading items to avoid errors caused by asynchronous behavior,
	// primarily for unit testing purposes.
	w.lockedFlushAddBuffer()

	return w.ready.Len()
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
		w.waiting.Ascend(func(item *item[T]) bool {
			items = append(items, item)
			return true
		})
		w.ready.Ascend(func(item *item[T]) bool {
			items = append(items, item)
			return true
		})
		w.lock.Unlock()

		w.log.V(5).Info("workqueue_items", "items", items)
	}
}

func lessWaiting[T comparable](a, b *item[T]) bool {
	if !a.ReadyAt.Equal(*b.ReadyAt) {
		return a.ReadyAt.Before(*b.ReadyAt)
	}
	return lessReady(a, b)
}

func lessReady[T comparable](a, b *item[T]) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
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
	ReplaceOrInsert(item T) (T, bool)
	Delete(item T) (T, bool)
	Ascend(iterator btree.ItemIteratorG[T])
	Len() int
}
