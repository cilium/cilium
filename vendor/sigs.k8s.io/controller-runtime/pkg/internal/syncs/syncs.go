package syncs

import (
	"context"
	"reflect"
	"sync"
)

// MergeChans returns a channel that is closed when any of the input channels are signaled.
// The caller must call the returned CancelFunc to ensure no resources are leaked.
func MergeChans[T any](chans ...<-chan T) (<-chan T, context.CancelFunc) {
	var once sync.Once
	out := make(chan T)
	cancel := make(chan T)
	cancelFunc := func() {
		once.Do(func() {
			close(cancel)
		})
		<-out
	}
	cases := make([]reflect.SelectCase, len(chans)+1)
	for i := range chans {
		cases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(chans[i]),
		}
	}
	cases[len(cases)-1] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(cancel),
	}
	go func() {
		defer close(out)
		_, _, _ = reflect.Select(cases)
	}()

	return out, cancelFunc
}
