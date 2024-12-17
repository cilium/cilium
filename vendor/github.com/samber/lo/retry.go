package lo

import (
	"sync"
	"time"
)

type debounce struct {
	after     time.Duration
	mu        *sync.Mutex
	timer     *time.Timer
	done      bool
	callbacks []func()
}

func (d *debounce) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.done {
		return
	}

	if d.timer != nil {
		d.timer.Stop()
	}

	d.timer = time.AfterFunc(d.after, func() {
		for i := range d.callbacks {
			d.callbacks[i]()
		}
	})
}

func (d *debounce) cancel() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}

	d.done = true
}

// NewDebounce creates a debounced instance that delays invoking functions given until after wait milliseconds have elapsed.
// Play: https://go.dev/play/p/mz32VMK2nqe
func NewDebounce(duration time.Duration, f ...func()) (func(), func()) {
	d := &debounce{
		after:     duration,
		mu:        new(sync.Mutex),
		timer:     nil,
		done:      false,
		callbacks: f,
	}

	return func() {
		d.reset()
	}, d.cancel
}

type debounceByItem struct {
	mu    *sync.Mutex
	timer *time.Timer
	count int
}

type debounceBy[T comparable] struct {
	after     time.Duration
	mu        *sync.Mutex
	items     map[T]*debounceByItem
	callbacks []func(key T, count int)
}

func (d *debounceBy[T]) reset(key T) {
	d.mu.Lock()
	if _, ok := d.items[key]; !ok {
		d.items[key] = &debounceByItem{
			mu:    new(sync.Mutex),
			timer: nil,
		}
	}

	item := d.items[key]

	d.mu.Unlock()

	item.mu.Lock()
	defer item.mu.Unlock()

	item.count++

	if item.timer != nil {
		item.timer.Stop()
	}

	item.timer = time.AfterFunc(d.after, func() {
		item.mu.Lock()
		count := item.count
		item.count = 0
		item.mu.Unlock()

		for i := range d.callbacks {
			d.callbacks[i](key, count)
		}

	})
}

func (d *debounceBy[T]) cancel(key T) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if item, ok := d.items[key]; ok {
		item.mu.Lock()

		if item.timer != nil {
			item.timer.Stop()
			item.timer = nil
		}

		item.mu.Unlock()

		delete(d.items, key)
	}
}

// NewDebounceBy creates a debounced instance for each distinct key, that delays invoking functions given until after wait milliseconds have elapsed.
// Play: https://go.dev/play/p/d3Vpt6pxhY8
func NewDebounceBy[T comparable](duration time.Duration, f ...func(key T, count int)) (func(key T), func(key T)) {
	d := &debounceBy[T]{
		after:     duration,
		mu:        new(sync.Mutex),
		items:     map[T]*debounceByItem{},
		callbacks: f,
	}

	return func(key T) {
		d.reset(key)
	}, d.cancel
}

// Attempt invokes a function N times until it returns valid output. Returning either the caught error or nil. When first argument is less than `1`, the function runs until a successful response is returned.
// Play: https://go.dev/play/p/3ggJZ2ZKcMj
func Attempt(maxIteration int, f func(index int) error) (int, error) {
	var err error

	for i := 0; maxIteration <= 0 || i < maxIteration; i++ {
		// for retries >= 0 {
		err = f(i)
		if err == nil {
			return i + 1, nil
		}
	}

	return maxIteration, err
}

// AttemptWithDelay invokes a function N times until it returns valid output,
// with a pause between each call. Returning either the caught error or nil.
// When first argument is less than `1`, the function runs until a successful
// response is returned.
// Play: https://go.dev/play/p/tVs6CygC7m1
func AttemptWithDelay(maxIteration int, delay time.Duration, f func(index int, duration time.Duration) error) (int, time.Duration, error) {
	var err error

	start := time.Now()

	for i := 0; maxIteration <= 0 || i < maxIteration; i++ {
		err = f(i, time.Since(start))
		if err == nil {
			return i + 1, time.Since(start), nil
		}

		if maxIteration <= 0 || i+1 < maxIteration {
			time.Sleep(delay)
		}
	}

	return maxIteration, time.Since(start), err
}

// AttemptWhile invokes a function N times until it returns valid output.
// Returning either the caught error or nil, and along with a bool value to identify
// whether it needs invoke function continuously. It will terminate the invoke
// immediately if second bool value is returned with falsy value. When first
// argument is less than `1`, the function runs until a successful response is
// returned.
func AttemptWhile(maxIteration int, f func(int) (error, bool)) (int, error) {
	var err error
	var shouldContinueInvoke bool

	for i := 0; maxIteration <= 0 || i < maxIteration; i++ {
		// for retries >= 0 {
		err, shouldContinueInvoke = f(i)
		if !shouldContinueInvoke { // if shouldContinueInvoke is false, then return immediately
			return i + 1, err
		}
		if err == nil {
			return i + 1, nil
		}
	}

	return maxIteration, err
}

// AttemptWhileWithDelay invokes a function N times until it returns valid output,
// with a pause between each call. Returning either the caught error or nil, and along
// with a bool value to identify whether it needs to invoke function continuously.
// It will terminate the invoke immediately if second bool value is returned with falsy
// value. When first argument is less than `1`, the function runs until a successful
// response is returned.
func AttemptWhileWithDelay(maxIteration int, delay time.Duration, f func(int, time.Duration) (error, bool)) (int, time.Duration, error) {
	var err error
	var shouldContinueInvoke bool

	start := time.Now()

	for i := 0; maxIteration <= 0 || i < maxIteration; i++ {
		err, shouldContinueInvoke = f(i, time.Since(start))
		if !shouldContinueInvoke { // if shouldContinueInvoke is false, then return immediately
			return i + 1, time.Since(start), err
		}
		if err == nil {
			return i + 1, time.Since(start), nil
		}

		if maxIteration <= 0 || i+1 < maxIteration {
			time.Sleep(delay)
		}
	}

	return maxIteration, time.Since(start), err
}

type transactionStep[T any] struct {
	exec       func(T) (T, error)
	onRollback func(T) T
}

// NewTransaction instantiate a new transaction.
func NewTransaction[T any]() *Transaction[T] {
	return &Transaction[T]{
		steps: []transactionStep[T]{},
	}
}

// Transaction implements a Saga pattern
type Transaction[T any] struct {
	steps []transactionStep[T]
}

// Then adds a step to the chain of callbacks. It returns the same Transaction.
func (t *Transaction[T]) Then(exec func(T) (T, error), onRollback func(T) T) *Transaction[T] {
	t.steps = append(t.steps, transactionStep[T]{
		exec:       exec,
		onRollback: onRollback,
	})

	return t
}

// Process runs the Transaction steps and rollbacks in case of errors.
func (t *Transaction[T]) Process(state T) (T, error) {
	var i int
	var err error

	for i < len(t.steps) {
		state, err = t.steps[i].exec(state)
		if err != nil {
			break
		}

		i++
	}

	if err == nil {
		return state, nil
	}

	for i > 0 {
		i--
		state = t.steps[i].onRollback(state)
	}

	return state, err
}

// throttle ?
