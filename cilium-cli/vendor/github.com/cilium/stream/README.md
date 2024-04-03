# Reactive streams for Go

A reactive streams library for Go in the spirit of Reactive Extensions (Rx) implemented
with generic functions. The library provides a rich set of utilities for wiring
event-passing in a complex application. Included are, for example, operators for
pubsub/fanning out (Multicast), for transforming (Map, Reduce), for rate limiting (Throttle)
and for buffering/coalescing (Buffer). New operators are easy to add as they are normal
top-level functions that take/return the `Observable` type.

## The Observable

The stream package provides the Observable interface for observing a stream of
values that can be cancelled and can be either infinite or finite in length.

The Observable interface is defined as:

```go
type Observable[T any] interface {
	Observe(ctx context.Context, next func(T), complete func(error))
}
```

The `next` function is called for each element in the stream. When the stream
is terminated or cancelled (via `ctx`) `next` will be called for remaining
elements and then `complete` after which neither function is invoked.

An Observable must adhere to the following rules:

* Observe() call must not block, e.g. be asynchronous by forking a goroutine.
* `next` must be called sequentially and never in parallel (previous call must complete
  before `next` can be called again).
* `complete` can be called at most once. `complete` must not be called in parallel with
  `next`. After `complete` is called neither `next` nor `complete` can be called again.
* if `ctx` is completed, calls to `next` should stop in short amount of time and `complete`
  must be called with `ctx.Err()`.

## Operators

The functions that operate on `Observable[T]` are divided into:

* [sources](sources.go) that create Observables
* [operators](operators.go) that transform Observables
* [sinks](sinks.go) that consume the Observable

Since Go's generics does not yet allow new type parameters in methods, all of these
are implemented as top-level functions rather than methods in the Observable interface.
This also makes it easy to add new operators as they're just normal functions.

## Creating an observable by hand

As a first example, we'll implement a simple source `Observable` that emits a single integer:

```go

type singleIntegerObservable int

func (num singleIntegerObservable) Observe(ctx context.Context, next func(int), complete func(error)) {
	go func() {
		next(int(num))
		complete(nil)
	}()
}
```

We can now try it out with the `Map` operator:

```go
func main() {
	var ten stream.Observable[int] = singleIntegerObservable(10)

	twenty := stream.Map(ten, func(x int) int) { return x * 2 })

	twenty.Observe(
		context.Background(),
		func(x int) {
			fmt.Printf("%d\n", x)
		},
		func(err error) {
			fmt.Printf("complete: %s\n", err)
		},
	)
}
```

Instead of defining a new type every time we want to implement `Observe`, we can use the `FuncObservable`
helper:

```go
func singleInt(x int) stream.Observable[int] {
	return stream.FuncObservable(
		func(ctx context.Context, next func(int), complete func(error)) error {
			next(x)
			complete(nil)
		},
	)
}
```

## Tour of the included operators

[Sources](sources.go) provide different ways of creating `Observable`s without
having to implement `Observe`:

```go
Just(10)                   // emits 10 and completes
Error(errors.New("oh no")) // completes with error
Empty()                    // completes with nil error
FromSlice([]int{1,2,3})    // emits 1,2,3 and completes
FromChannel(in)            // emits items from the given channel
Range(0,3)                 // emits 0,1,2 and completes


// Multicast creates an observable that emits items to all observers.
src, next, complete := Multicast[int]()

ch1 := ToChannel(ctx, src)
ch2 := ToChannel(ctx, src)
next(1)
<-ch1 // 1
<-ch2 // 1
```

[Operators](operators.go) transform streams in different ways:
```go
// Map[A, B any](src Observable[A], apply func(A) B) Observable[B]
Map(src, apply)            // applies function 'apply' to each item.

// Filter[T any](src Observable[T], filter func(T) bool) Observable[T]
Filter(src, filter)        // applies function 'filter' to each item. If 'filter' returns false the
                           // item is dropped.

// Reduce[T, Result any](src Observable[T], init Result, reduce func(T, Result) Result) Observable[Result]
// Applies function 'reduce' to each item to "reduce" the stream into a single value.
Reduce(Range(0, 3), 0, func(x, result int) int { return x + result }) // 0 + 1 + 2 = 3

// ToMulticast[T any](src Observable[T], opts ...MulticastOpt) (mcast Observable[T], connect func(context.Context))
// Converts an observable into a multicast observable
src, connect := ToMulticast(Range(1,5))
ch1 := ToChannel(ctx, src)
ch2 := ToChannel(ctx, src)
connect(ctx) // start observing the parent observable
<-ch1 // 1
<-ch2 // 1
```

[Sinks](stream/sinks.go) consume streams:
```go
// First[T any](ctx context.Context, src Observable[T]) (item T, err error)
// Takes the first item from the observable and then cancels it.
item, err := First(ctx, src)

// ToSlice[T any](ctx context.Context, src Observable[T]) (items []T, err error)
// Converts the observable into a slice.
items, err := ToSlice(ctx, src)

// ToChannel[T any](ctx context.Context, src Observable[T], opts ...ToChannelOpt) <-chan T
// Converts the observable into a channel.
items := ToChannel(ctx, src)

// Discard[T any](ctx context.Context, src Observable[T]) error
// Consumes the observable by discarding the elements.
Discard(ctx, src)
```

