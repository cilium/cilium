# Workerpool

[![Go Reference](https://pkg.go.dev/badge/github.com/cilium/workerpool.svg)](https://pkg.go.dev/github.com/cilium/workerpool)
[![CI](https://github.com/cilium/workerpool/workflows/Tests/badge.svg)](https://github.com/cilium/workerpool/actions?query=workflow%3ATests)
[![Go Report Card](https://goreportcard.com/badge/github.com/cilium/workerpool)](https://goreportcard.com/report/github.com/cilium/workerpool)

Package workerpool implements a concurrency limiting worker pool. Worker
routines are spawned on demand as tasks are submitted.

This package is mostly useful when tasks are CPU bound and spawning too many
routines would be detrimental to performance. It features a straightforward API
and no external dependencies. See the section below for a usage example.

## Example

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
func IsPrime(n int64) bool {
	if n < 2 {
		return false
	}
	for p := int64(2); p*p <= n; p++ {
		if n%p == 0 {
			return false
		}
	}
	return true
}

func main() {
	wp := workerpool.New(runtime.NumCPU())
	for i, n := 0, int64(1_000_000_000_000_000_000); n < 1_000_000_000_000_000_100; i, n = i+1, n+1 {
		n := n // https://golang.org/doc/faq#closures_and_goroutines
		id := fmt.Sprintf("task #%d", i)
		// Use Submit to submit tasks for processing. Submit blocks when no
		// worker is available to pick up the task.
		err := wp.Submit(id, func(_ context.Context) error {
			fmt.Println("isprime", n)
			if IsPrime(n) {
				fmt.Println(n, "is prime!")
			}
			return nil
		})
		// Submit fails when the pool is closed (ErrClosed) or being drained
		// (ErrDrained). Check for the error when appropriate.
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

	// Close should be called once the worker pool is no longer necessary.
	if err := wp.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
```
