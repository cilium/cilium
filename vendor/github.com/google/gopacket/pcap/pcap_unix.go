// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
// +build !windows

package pcap

/*
#include <stdlib.h>
#include <pcap.h>

// pcap_wait returns when the next packet is available or the timeout expires.
// Since it uses pcap_get_selectable_fd, it will not work in Windows.
int pcap_wait(pcap_t *p, int usec) {
	fd_set fds;
	int fd;
	struct timeval tv;

	fd = pcap_get_selectable_fd(p);
	if(fd < 0) {
		return fd;
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	tv.tv_sec = 0;
	tv.tv_usec = usec;

	if(usec != 0) {
		return select(1, &fds, NULL, NULL, &tv);
	}

	// block indefinitely if no timeout provided
	return select(1, &fds, NULL, NULL, NULL);
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func (p *Handle) openLive() error {
	buf := (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))

	// Change the device to non-blocking, we'll use pcap_wait to wait until the
	// handle is ready to read.
	if v := C.pcap_setnonblock(p.cptr, 1, buf); v == -1 {
		return errors.New(C.GoString(buf))
	}

	return nil
}

// waitForPacket waits for a packet or for the timeout to expire.
func (p *Handle) waitForPacket() {
	if p.timeout == BlockForever {
		C.pcap_wait(p.cptr, 0)
		return
	}

	// need to wait less than the read timeout according to pcap documentation.
	// timeoutMillis rounds up to at least one millisecond so we can safely
	// subtract up to a millisecond.
	usec := timeoutMillis(p.timeout) * 1000
	usec -= 100

	C.pcap_wait(p.cptr, usec)
}
