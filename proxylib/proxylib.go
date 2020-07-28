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

package main

/*
#include "proxylib/types.h"
*/
import "C"

import (
	"github.com/cilium/cilium/proxylib/accesslog"
	_ "github.com/cilium/cilium/proxylib/cassandra"
	_ "github.com/cilium/cilium/proxylib/kafka"
	_ "github.com/cilium/cilium/proxylib/memcached"
	"github.com/cilium/cilium/proxylib/npds"
	. "github.com/cilium/cilium/proxylib/proxylib"
	_ "github.com/cilium/cilium/proxylib/r2d2"
	_ "github.com/cilium/cilium/proxylib/testparsers"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/lock"
	log "github.com/sirupsen/logrus"
)

var (
	// mutex protects connections
	mutex lock.RWMutex
	// Key uint64 is a connection ID allocated by Envoy, practically a monotonically increasing number
	connections map[uint64]*Connection = make(map[uint64]*Connection)
)

func init() {
	log.Info("proxylib: Initializing library")
}

// Copy value string from C-memory to Go-memory.
// Go strings are immutable, but byte slices are not. Converting to a byte slice will thus
// copy the memory.
func strcpy(str string) string {
	return string(([]byte(str))[0:])
}

// OnNewConnection is used to register a new connection of protocol 'proto'.
// Note that the 'origBuf' and replyBuf' type '*[]byte' corresponds to 'InjectBuf' type, but due to
// cgo export restrictions we can't use the go type in the prototype.
//export OnNewConnection
func OnNewConnection(instanceId uint64, proto string, connectionId uint64, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string, origBuf, replyBuf *[]byte) C.FilterResult {
	instance := FindInstance(instanceId)
	if instance == nil {
		return C.FILTER_INVALID_INSTANCE
	}

	err, conn := NewConnection(instance, strcpy(proto), connectionId, ingress, srcId, dstId, strcpy(srcAddr), strcpy(dstAddr), strcpy(policyName), origBuf, replyBuf)
	if err == nil {
		mutex.Lock()
		connections[connectionId] = conn
		mutex.Unlock()
		return C.FILTER_OK
	}
	if res, ok := err.(FilterResult); ok {
		return C.FilterResult(res)
	}
	return C.FILTER_UNKNOWN_ERROR
}

// Each connection is assumed to be called from a single thread, so accessing connection metadata
// does not need protection.
//
// OnData gets all the unparsed data the datapath has received so far. The data is provided to the parser
// associated with the connection, and the parser is expected to find if the data frame contains enough data
// to make a PASS/DROP decision for the whole data frame. Note that the whole data frame need not be received,
// if the decision including the length of the data frame in bytes can be determined based on the beginning of
// the data frame only (e.g., headers including the length of the data frame). The parser returns a decision
// with the number of bytes on which the decision applies. If more data is available, then the parser will be
// called again with the remaining data. Parser needs to return MORE if a decision can't be made with
// the available data, including the minimum number of additional bytes that is needed before the parser is
// called again.
//
// The parser can also inject at arbitrary points in the data stream. This is indecated by an INJECT operation
// with the number of bytes to be injected. The actual bytes to be injected are provided via an Inject()
// callback prior to returning the INJECT operation. The Inject() callback operates on a limited size buffer
// provided by the datapath, and multiple INJECT operations may be needed to inject large amounts of data.
// Since we get the data on one direction at a time, any frames to be injected in the reverse direction
// are placed in the reverse direction buffer, from where the datapath injects the data before calling
// us again for the reverse direction input.
//
//export OnData
func OnData(connectionId uint64, reply, endStream bool, data *[][]byte, filterOps *[][2]int64) C.FilterResult {
	// Find the connection
	mutex.RLock()
	connection, ok := connections[connectionId]
	mutex.RUnlock()
	if !ok {
		return C.FILTER_UNKNOWN_CONNECTION
	}

	return C.FilterResult(connection.OnData(reply, endStream, data, filterOps))
}

// Make this more general connection event callback
//export Close
func Close(connectionId uint64) {
	mutex.Lock()
	delete(connections, connectionId)
	mutex.Unlock()
}

// OpenModule is called before any other APIs.
// Called concurrently by different filter instances.
// Returns a library instance ID that must be passed to all other API calls.
// Calls with the same parameters will return the same instance.
// Zero return value indicates an error.
//export OpenModule
func OpenModule(params [][2]string, debug bool) uint64 {
	var accessLogPath, xdsPath, nodeID string
	for i := range params {
		key := params[i][0]
		value := strcpy(params[i][1])

		switch key {
		case "access-log-path":
			accessLogPath = value
		case "xds-path":
			xdsPath = value
		case "node-id":
			nodeID = value
		default:
			return 0
		}
	}

	if debug {
		mutex.Lock()
		log.SetLevel(log.DebugLevel)
		flowdebug.Enable()
		mutex.Unlock()
	}
	// Copy strings from C-memory to Go-memory so that the string remains valid
	// also after this function returns
	return OpenInstance(nodeID, xdsPath, npds.NewClient, accessLogPath, accesslog.NewClient)
}

//export CloseModule
func CloseModule(id uint64) {
	CloseInstance(id)
}

// Must have empty main
func main() {}
