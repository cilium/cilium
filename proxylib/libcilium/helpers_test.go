// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package libcilium

// These helpers must be defined in the main package so that the exported shared library functions
// can be called, as the C types used in the prototypes are only available from within the main
// package.
//
// These can not be defined in '_test.go' files, as Go test is not compatible with Cgo.

import (
	"testing"

	. "github.com/cilium/cilium/proxylib/proxylib"
)

func numConnections() int {
	mutex.Lock()
	defer mutex.Unlock()
	return len(connections)
}

func checkConnectionCount(t *testing.T, expConns int) {
	t.Helper()
	nConns := numConnections()
	if nConns != expConns {
		t.Errorf("Number of connections does not match (have %d, but should be %d)", nConns, expConns)
	}
}

func checkConnections(t *testing.T, res, expected FilterResult, expConns int) {
	t.Helper()
	if res != expected {
		t.Errorf("OnNewConnection(): Invalid result, have %s, expected %s", res.Error(), expected.Error())
	}
	checkConnectionCount(t, expConns)
}

func CheckOnNewConnection(t *testing.T, instanceId uint64, proto string, connectionId uint64, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string, bufSize int, expResult FilterResult, expNumConnections int) *byte {
	t.Helper()
	origBuf := make([]byte, 0, bufSize)
	replyBuf := make([]byte, 1, bufSize)
	replyBufAddr := &replyBuf[0]
	replyBuf = replyBuf[:0] // make the buffer empty again

	res := FilterResult(OnNewConnection(instanceId, proto, connectionId, ingress, srcId, dstId, srcAddr, dstAddr, policyName, &origBuf, &replyBuf))
	checkConnections(t, res, expResult, expNumConnections)

	return replyBufAddr
}

func CheckClose(t *testing.T, connectionId uint64, replyBufAddr *byte, n int) {
	t.Helper()
	checkConnectionCount(t, n)

	// Find the connection
	mutex.Lock()
	connection, ok := connections[connectionId]
	mutex.Unlock()
	if !ok {
		t.Errorf("OnData(): Connection %d not found!", connectionId)
	} else if replyBufAddr != nil && len(*connection.ReplyBuf) > 0 && replyBufAddr != &(*connection.ReplyBuf)[0] {
		t.Error("OnData(): Reply injection buffer reallocated while it must not be!")
	}

	Close(connectionId)

	checkConnectionCount(t, n-1)
}

type ExpFilterOp struct {
	op      OpType
	n_bytes int
}

func checkOps(ops [][2]int64, exp []ExpFilterOp) bool {
	if len(ops) != len(exp) {
		return false
	} else {
		for i, op := range ops {
			if op[0] != int64(exp[i].op) || op[1] != int64(exp[i].n_bytes) {
				return false
			}
		}
	}
	return true
}

func checkBuf(t *testing.T, buf InjectBuf, expected string) {
	t.Helper()
	if len(*buf) < len(expected) {
		t.Log("Inject buffer too small, data truncated")
		expected = expected[:len(*buf)] // truncate to buffer length
	}
	if string(*buf) != expected {
		t.Errorf("OnData(): Expected inject buffer to be %s, buf have: %s", expected, *buf)
	}
}

func checkOnData(t *testing.T, res, expected FilterResult, ops [][2]int64, expOps []ExpFilterOp) {
	t.Helper()
	if res != expected {
		t.Errorf("OnData(): Invalid result, have %s, expected %s", res.Error(), expected.Error())
	}
	if !checkOps(ops, expOps) {
		t.Errorf("OnData(): Unexpected filter operations: %v, expected %v", ops, expOps)
	}
}

func CheckOnData(t *testing.T, connectionId uint64, reply, endStream bool, data *[][]byte, expOps []ExpFilterOp, expResult FilterResult, expReplyBuf string) {
	t.Helper()

	// Find the connection
	mutex.Lock()
	connection, ok := connections[connectionId]
	mutex.Unlock()
	if !ok && expResult != UNKNOWN_CONNECTION {
		t.Errorf("OnData(): Connection %d not found!", connectionId)
	}

	ops := make([][2]int64, 0, 1+len(expOps)*2)

	res := FilterResult(OnData(connectionId, reply, endStream, data, &ops))

	checkOnData(t, res, expResult, ops, expOps)

	if ok {
		replyBuf := connection.ReplyBuf
		checkBuf(t, replyBuf, expReplyBuf)
		*replyBuf = (*replyBuf)[:0] // make empty again
	}
}
