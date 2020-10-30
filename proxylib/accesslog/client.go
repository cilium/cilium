// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package accesslog

import (
	"net"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/proxy/go/cilium/api"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	connected uint32 // Accessed atomically without locking
	path      string
	mutex     lock.Mutex     // Used to protect opening the connection
	conn      unsafe.Pointer // Read atomically without locking
}

func (cl *Client) connect() *net.UnixConn {
	if cl.path == "" {
		return nil
	}

	if atomic.LoadUint32(&cl.connected) > 0 {
		// Guaranteed to be non-nil
		return (*net.UnixConn)(atomic.LoadPointer(&cl.conn))
	}

	cl.mutex.Lock()
	defer cl.mutex.Unlock()

	// Safe to read cl.conn while holding the mutex
	conn := (*net.UnixConn)(cl.conn)

	// Did someone else connect while we were contending on the lock?
	// cl.connected may be written to by others concurrently
	if atomic.LoadUint32(&cl.connected) > 0 {
		return conn
	}

	if conn != nil {
		conn.Close() // not setting conn to nil!
	}
	log.Debugf("Accesslog: Connecting to Cilium access log socket: %s", cl.path)
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: cl.path, Net: "unixpacket"})
	if err != nil {
		log.WithError(err).Error("Accesslog: DialUnix() failed")
		return nil
	}

	atomic.StorePointer(&cl.conn, unsafe.Pointer(conn))

	// Always have a non-nil 'cl.conn' after 'cl.connected' is set for the first time!
	atomic.StoreUint32(&cl.connected, 1)
	return conn
}

func (cl *Client) Log(pblog *cilium.LogEntry) {
	if conn := cl.connect(); conn != nil {
		// Encode
		logmsg, err := proto.Marshal(pblog)
		if err != nil {
			log.WithError(err).Error("Accesslog: Protobuf marshaling error")
			return
		}

		// Write
		_, err = conn.Write(logmsg)
		if err != nil {
			log.WithError(err).Error("Accesslog: Write() failed")
			atomic.StoreUint32(&cl.connected, 0) // Mark connection as broken
		}
	} else {
		log.Debugf("Accesslog: No connection, cannot send: %s", pblog.String())
	}
}

func (c *Client) Path() string {
	return c.path
}

func NewClient(accessLogPath string) proxylib.AccessLogger {
	client := &Client{
		path: accessLogPath,
	}
	client.connect()
	return client
}

func (cl *Client) Close() {
	conn := (*net.UnixConn)(atomic.LoadPointer(&cl.conn))
	if conn != nil {
		conn.Close()
	}
}
