# Workerpool

[![Go Reference](https://pkg.go.dev/badge/github.com/cilium/workerpool.svg)](https://pkg.go.dev/github.com/cilium/workerpool)
[![CI](https://github.com/cilium/workerpool/workflows/Tests/badge.svg)](https://github.com/cilium/workerpool/actions?query=workflow%3ATests)
[![Go Report Card](https://goreportcard.com/badge/github.com/cilium/workerpool)](https://goreportcard.com/report/github.com/cilium/workerpool)

**A concurrency-limiting worker pool for Go with backpressure and zero
dependencies.**

Perfect for CPU-bound tasks that need controlled parallelism without
unbounded queuing.

## Features

- ✅ **Backpressure by design** - Blocks on submit when workers are busy
  (no unbounded queues)
- ✅ **On-demand workers** - Spawns workers as needed, up to configured
  limit
- ✅ **Two result modes** - Collect via `Drain()` or stream via callback
- ✅ **Context-aware** - Full cancellation support for graceful shutdown
- ✅ **Zero dependencies** - Pure standard library
- ✅ **Simple API** - Submit, Drain, Close. That's it.

## Installation

```bash
go get github.com/cilium/workerpool
```

## Quick Start

```go
wp := workerpool.New(runtime.NumCPU())
defer wp.Close()

// Submit tasks (blocks when all workers are busy)
err := wp.Submit("task-1", func(ctx context.Context) error {
    // Your CPU-bound work here
    return process(data)
})

// Collect results
tasks, _ := wp.Drain()
for _, task := range tasks {
    if err := task.Err(); err != nil {
        log.Printf("Task %s failed: %v", task, err)
    }
}
```

## When to Use This

**Use workerpool when:**
- Tasks are CPU-bound and need parallelism control
- You want backpressure (block submission instead of queuing unbounded
  tasks)
- You need simple, predictable concurrency limiting

**Don't use if:**
- You need I/O-bound task handling (consider channels or goroutines
  directly)
- You want automatic retries, priorities, or complex scheduling
- You need persistent job queues (use a proper job queue)

## Usage Patterns

### Pattern 1: Batch Processing with Drain

Process tasks in batches and collect all results at once.

<details>
<summary>Click to expand full example</summary>

```go
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/workerpool"
)

// IsPrime returns true if n is prime, false otherwise.
func IsPrime(ctx context.Context, n int64) bool {
	if n < 2 {
		return false
	}
	for p := int64(2); p*p <= n; p++ {
		// Check for cancellation periodically (every 10000 iterations)
		if p%10000 == 0 {
			select {
			case <-ctx.Done():
				return false
			default:
			}
		}
		if n%p == 0 {
			return false
		}
	}
	return true
}

func main() {
	wp := workerpool.New(runtime.NumCPU())
	// Defer Close to ensure cleanup on early return (e.g., errors during Submit).
	// Close sends cancellation to running tasks and waits for them to complete.
	// It's safe to call Close multiple times; subsequent calls return ErrClosed.
	defer func() { _ = wp.Close() }()

	for i, n := 0, int64(1_000_000_000_000_000_000); i < 100; i, n = i+1, n+1 {
		id := fmt.Sprintf("task #%d", i)
		// Use Submit to submit tasks for processing. Submit blocks when no
		// worker is available to pick up the task.
		err := wp.Submit(id, func(ctx context.Context) error {
			fmt.Println("isprime", n)
			if IsPrime(ctx, n) {
				fmt.Println(n, "is prime!")
			}
			return nil
		})
		// Submit fails when the pool is closed (ErrClosed), being drained
		// (ErrDraining), or the parent context is done (context.Canceled).
		// Check for the error when appropriate.
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	// Drain prevents submitting new tasks and blocks until all submitted tasks
	// complete.
	tasks, err := wp.Drain()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// Iterating over the results is useful if non-nil errors can be expected.
	for _, task := range tasks {
		// Err returns the error that the task returned after execution.
		if err := task.Err(); err != nil {
			fmt.Println("task", task, "failed:", err)
		}
	}

	// Close is called here explicitly to check for errors. The deferred Close
	// will also run but returns ErrClosed (which we can ignore on defer).
	if err := wp.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
```

</details>

### Pattern 2: Streaming Results with Callback

Use `WithResultCallback` to process each result as it completes rather
than accumulating them for a later `Drain` call. The callback receives a
`Result`, which extends `Task` with a `Duration()` method reporting how
long the task took to execute. This is useful for logging, metrics, or
long-running pools where unbounded result accumulation is undesirable.

<details>
<summary>Click to expand full example</summary>

```go
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/workerpool"
)

func main() {
	wp := workerpool.New(runtime.NumCPU(), workerpool.WithResultCallback(func(r workerpool.Result) {
		if err := r.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "task %s failed after %s: %v\n", r, r.Duration(), err)
		} else {
			fmt.Printf("task %s completed in %s\n", r, r.Duration())
		}
	}))
	defer func() { _ = wp.Close() }()

	for i, n := 0, int64(1_000_000_000_000_000_000); i < 100; i, n = i+1, n+1 {
		id := fmt.Sprintf("task #%d", i)
		err := wp.Submit(id, func(ctx context.Context) error {
			if IsPrime(ctx, n) {
				fmt.Println(n, "is prime!")
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}

	// Close waits for all in-flight tasks to complete before returning,
	// ensuring all callback invocations have finished.
	if err := wp.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
```

</details>

## Important Notes

> [!WARNING]
> **Result accumulation**: Without `WithResultCallback`, results accumulate
> in memory until drained. For large workloads, drain periodically or use
> the callback mode.

> [!NOTE]
> **Backpressure behavior**: `Submit()` blocks when no workers are
> available. This is intentional to prevent unbounded queuing. Queue tasks
> yourself if needed.

> [!IMPORTANT]
> **Cleanup**: Always `defer wp.Close()` to ensure graceful shutdown and
> context cancellation.

## Documentation

Full API documentation: https://pkg.go.dev/github.com/cilium/workerpool
