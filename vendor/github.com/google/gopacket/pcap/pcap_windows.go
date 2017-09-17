// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

func (p *Handle) openLive() error {
	// do nothing
}

// waitForPacket waits for a packet or for the timeout to expire.
func (p *Handle) waitForPacket() {
	// can't use select() so instead just switch goroutines
	runtime.Gosched()
}
