package statedb

import (
	"context"
	"slices"
	"sync"
)

const watchSetChunkSize = 16

// WatchSet is a set of watch channels that can be waited on.
type WatchSet struct {
	mu    sync.Mutex
	chans []<-chan struct{}
}

func NewWatchSet() *WatchSet {
	return &WatchSet{
		chans: make([]<-chan struct{}, 0, watchSetChunkSize),
	}
}

// Add a channel to the watch set.
func (ws *WatchSet) Add(chans ...<-chan struct{}) {
	ws.mu.Lock()
	for _, ch := range chans {
		ws.chans = append(ws.chans, ch)
	}
	ws.mu.Unlock()
}

func (ws *WatchSet) Clear() {
	ws.mu.Lock()
	ws.chans = ws.chans[:0]
	ws.mu.Unlock()
}

// Wait for any channel in the watch set to close. The
// watch set is cleared when this method returns.
func (ws *WatchSet) Wait(ctx context.Context) error {
	ws.mu.Lock()
	defer func() {
		ws.chans = ws.chans[:0]
		ws.mu.Unlock()
	}()

	// No channels to watch? Just watch the context.
	if len(ws.chans) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	// Collect the channels into a slice. The slice length is rounded to a full
	// chunk size.
	chunkSize := 16
	roundedSize := len(ws.chans) + (chunkSize - len(ws.chans)%chunkSize)
	ws.chans = slices.Grow(ws.chans, roundedSize)[:roundedSize]

	if len(ws.chans) <= chunkSize {
		watch16(ctx.Done(), ws.chans)
		return ctx.Err()
	}

	// More than one chunk. Fork goroutines to watch each chunk. The first chunk
	// that completes will cancel the context and stop the other goroutines.
	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for chunk := range slices.Chunk(ws.chans, chunkSize) {
		wg.Add(1)
		go func() {
			defer cancel()
			defer wg.Done()
			chunk = slices.Clone(chunk)
			watch16(innerCtx.Done(), chunk)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

func watch16(stop <-chan struct{}, chans []<-chan struct{}) {
	select {
	case <-stop:
	case <-chans[0]:
	case <-chans[1]:
	case <-chans[2]:
	case <-chans[3]:
	case <-chans[4]:
	case <-chans[5]:
	case <-chans[6]:
	case <-chans[7]:
	case <-chans[8]:
	case <-chans[9]:
	case <-chans[10]:
	case <-chans[11]:
	case <-chans[12]:
	case <-chans[13]:
	case <-chans[14]:
	case <-chans[15]:
	}
}
