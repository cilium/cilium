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

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/golang/protobuf/proto"

	log "github.com/sirupsen/logrus"
)

type Client struct {
	connected uint32     // Accessed atomically without locking
	mutex     lock.Mutex // Used to protect opening the connection
	path      string
	conn      unsafe.Pointer // Read atomically without locking
}

func (cl *Client) connect() *net.UnixConn {
	if atomic.LoadUint32(&cl.connected) > 0 {
		// Guaranteed to be non-nil
		return (*net.UnixConn)(atomic.LoadPointer(&cl.conn))
	}

	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	if cl.path == "" {
		return nil
	}

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
		log.Errorf("Accesslog: DialUnix() failed: %v", err)
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
			log.Errorf("Accesslog: Protobuf marshaling error: %v", err)
			return
		}

		// Write
		_, err = conn.Write(logmsg)
		if err != nil {
			log.Errorf("Accesslog: Write() failed: %v", err)
			atomic.StoreUint32(&cl.connected, 0) // Mark connection as broken
		} else {
			log.Debugf("Accesslog: Wrote: %s", pblog.String())
		}
	} else {
		log.Debugf("Accesslog: No connection, cannot send: %s", pblog.String())
	}
}

var client *Client

func init() {
	client = &Client{}
}

func SetPath(accessLogPath string) {
	client.mutex.Lock()
	client.path = accessLogPath
	atomic.StoreUint32(&client.connected, 0) // Mark connection as broken
	client.mutex.Unlock()
	client.connect()
	return
}

func Log(pblog *cilium.LogEntry) {
	client.Log(pblog)
}
