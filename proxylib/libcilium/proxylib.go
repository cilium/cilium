// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package libcilium

import (
	"github.com/sirupsen/logrus"

	_ "github.com/cilium/cilium/proxylib/cassandra"
	_ "github.com/cilium/cilium/proxylib/kafka"
	_ "github.com/cilium/cilium/proxylib/memcached"
	_ "github.com/cilium/cilium/proxylib/r2d2"
	_ "github.com/cilium/cilium/proxylib/testparsers"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/npds"
	"github.com/cilium/cilium/proxylib/proxylib"
)

var (
	// mutex protects connections
	mutex lock.RWMutex
	// Key uint64 is a connection ID allocated by Envoy, practically a monotonically increasing number
	connections map[uint64]*proxylib.Connection = make(map[uint64]*proxylib.Connection)
)

// Copy value string from C-memory to Go-memory.
// Go strings are immutable, but byte slices are not. Converting to a byte slice will thus
// copy the memory.
func strcpy(str string) string {
	return string(([]byte(str))[0:])
}

func OnNewConnection(instanceId uint64, proto string, connectionId uint64, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string, origBuf, replyBuf *[]byte) proxylib.FilterResult {
	instance := proxylib.FindInstance(instanceId)
	if instance == nil {
		return proxylib.INVALID_INSTANCE
	}

	err, conn := proxylib.NewConnection(instance, strcpy(proto), connectionId, ingress, srcId, dstId, strcpy(srcAddr), strcpy(dstAddr), strcpy(policyName), origBuf, replyBuf)
	if err == nil {
		mutex.Lock()
		connections[connectionId] = conn
		mutex.Unlock()
		return proxylib.OK
	}
	if res, ok := err.(proxylib.FilterResult); ok {
		return res
	}
	return proxylib.UNKNOWN_ERROR
}

func OnData(connectionId uint64, reply, endStream bool, data *[][]byte, filterOps *[][2]int64) proxylib.FilterResult {
	// Find the connection
	mutex.RLock()
	connection, ok := connections[connectionId]
	mutex.RUnlock()
	if !ok {
		return proxylib.UNKNOWN_CONNECTION
	}

	return connection.OnData(reply, endStream, data, filterOps)
}

func Close(connectionId uint64) {
	mutex.Lock()
	delete(connections, connectionId)
	mutex.Unlock()
}

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
		logrus.SetLevel(logrus.DebugLevel)
		flowdebug.Enable()
		mutex.Unlock()
	}
	// Copy strings from C-memory to Go-memory so that the string remains valid
	// also after this function returns
	return proxylib.OpenInstance(nodeID, xdsPath, npds.NewClient, accessLogPath, accesslog.NewClient)
}

func CloseModule(id uint64) {
	proxylib.CloseInstance(id)
}
