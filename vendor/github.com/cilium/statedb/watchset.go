// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"time"
)

// WatchSet is a set of watch channels that can be waited on.
type WatchSet struct {
	mu    sync.Mutex
	chans channelSet

	cases []reflect.SelectCase // for reuse in Wait()
}

type channelSet = map[<-chan struct{}]struct{}

func NewWatchSet() *WatchSet {
	return &WatchSet{
		chans: channelSet{},
	}
}

// Add channel(s) to the watch set
func (ws *WatchSet) Add(chans ...<-chan struct{}) {
	ws.mu.Lock()
	for _, ch := range chans {
		ws.chans[ch] = struct{}{}
	}
	ws.mu.Unlock()
}

// Clear the channels from the WatchSet
func (ws *WatchSet) Clear() {
	ws.mu.Lock()
	clear(ws.chans)
	ws.mu.Unlock()
}

// Has returns true if the WatchSet has the channel
func (ws *WatchSet) Has(ch <-chan struct{}) bool {
	ws.mu.Lock()
	_, found := ws.chans[ch]
	ws.mu.Unlock()
	return found
}

// HasAny returns true if the WatchSet has any of the given channels
func (ws *WatchSet) HasAny(chans []<-chan struct{}) bool {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	for _, ch := range chans {
		if _, found := ws.chans[ch]; found {
			return true
		}
	}
	return false
}

// Merge channels from another WatchSet
func (ws *WatchSet) Merge(other *WatchSet) {
	other.mu.Lock()
	defer other.mu.Unlock()
	ws.mu.Lock()
	defer ws.mu.Unlock()
	for ch := range other.chans {
		ws.chans[ch] = struct{}{}
	}
}

// Wait for channels in the watch set to close or the context is cancelled.
// After the first closed channel is seen Wait will wait [settleTime] for
// more closed channels.
// If [settleTime] is 0 waits until [ctx] cancelled or any channel closes.
// Returns the closed channels and removes them from the set.
func (ws *WatchSet) Wait(ctx context.Context, settleTime time.Duration) ([]<-chan struct{}, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	// No channels to watch? Just watch the context.
	if len(ws.chans) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	// Construct []SelectCase slice. Reuse the previous allocation.
	ws.cases = slices.Grow(ws.cases, 1+len(ws.chans))
	cases := ws.cases[:1+len(ws.chans)]

	// Add [ctx.Done()] to stop when [ctx] is cancelled.
	cases[0] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	}

	// Add the cases from the watch set.
	casesIndex := 1
	for ch := range ws.chans {
		cases[casesIndex] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		}
		casesIndex++
	}

	var closedChannels []<-chan struct{}

	// At the end remove the closed channels from the watch set.
	defer func() {
		for _, ch := range closedChannels {
			delete(ws.chans, ch)
		}
	}()

	// Wait for the first channel to close and shift it out from [cases]
	chosen, _, _ := reflect.Select(cases)
	if chosen == 0 {
		return nil, ctx.Err()
	}
	closedChannels = append(closedChannels, cases[chosen].Chan.Interface().(<-chan struct{}))
	cases[chosen] = cases[len(cases)-1]
	cases = cases[:len(cases)-1]

	// If nothing else than context channel remains or we don't want to wait for further channels
	// to close then we're done.
	if len(cases) == 1 || settleTime == 0 {
		return closedChannels, nil
	}

	// Swap out the 'ctx.Done()' to a context that times out when [settleTime] expires.
	settleCtx, cancel := context.WithTimeout(ctx, settleTime)
	defer cancel()
	cases[0].Chan = reflect.ValueOf(settleCtx.Done())

	for len(cases) > 1 {
		chosen, _, _ := reflect.Select(cases)
		if chosen == 0 /* settleCtx.Done() */ {
			break
		}
		closedChannels = append(closedChannels, cases[chosen].Chan.Interface().(<-chan struct{}))
		cases[chosen] = cases[len(cases)-1]
		cases = cases[:len(cases)-1]
	}

	return closedChannels, ctx.Err()
}
