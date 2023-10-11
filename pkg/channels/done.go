// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package channels

type DoneChan = <-chan struct{}

var ClosedDoneChan DoneChan

func init() {
	ch := make(chan struct{})
	close(ch)
	ClosedDoneChan = ch
}
