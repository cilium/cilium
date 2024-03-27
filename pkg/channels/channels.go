// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package channels

type DoneChan <-chan struct{}

var ClosedDoneChan DoneChan

func init() {
	ch := make(chan struct{})
	close(ch)
	ClosedDoneChan = ch
}

// Merge merges a slice of channels and returns a channel that is
// closed when all the merged channels are closed.
// Each merged channel is expected to be used to notify the receiver
// exactly once, by closing it, and never to be used again thereafter.
// In other words, Merge does not support multiple notifications sent
// through the same channel. This is done to avoid spawning N+1
// goroutines to receive independently from each channel.
func Merge(cs ...<-chan struct{}) <-chan struct{} {
	out := make(chan struct{})
	go func() {
		for _, c := range cs {
			<-c
		}
		close(out)
	}()
	return out
}
