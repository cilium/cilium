package main

import (
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/envoy/cilium"

	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"

	log "github.com/sirupsen/logrus"
)

func TestInitModule(t *testing.T) {
	if !InitModule("") {
		t.Error("InitModule() with empty access log name failed")
	}

	logServer := startAccessLogServer(t, "access_log.sock")
	defer logServer.close()

	if !InitModule(logServer.path) {
		t.Errorf("InitModule() with access log path %s failed", logServer.path)
	}
}

func numConnections() int {
	mutex.Lock()
	defer mutex.Unlock()
	return len(connections)
}

func checkConnections(t *testing.T, expected, res FilterResult, expConns int) {
	t.Helper()
	if res != expected {
		t.Errorf("OnNewConnection(): Invalid result, have %s, expected %s", res.String(), expected.String())
	}
	nConns := numConnections()
	if nConns != expConns {
		t.Errorf("Number of connections does not match (have %d, but should be %d)", nConns, expConns)
	}
}

func TestOnNewConnection(t *testing.T) {
	if !InitModule("") {
		t.Error("InitModule() with empty access log name failed")
	}

	origBuf := make([]byte, 0, 80)
	replyBuf := make([]byte, 0, 80)

	// Unkhown parser
	expected := FILTER_UNKNOWN_PARSER
	res := OnNewConnection("invalid-parser-should-not-exist", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "policy-1", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 0)

	// Non-numeric destination port
	expected = FILTER_INVALID_ADDRESS
	res = OnNewConnection("passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:XYZ", "policy-1", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 0)

	// Missing Destination port
	expected = FILTER_INVALID_ADDRESS
	res = OnNewConnection("passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2", "policy-1", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 0)

	// Zero Destination port is reserved for wildcarding
	expected = FILTER_INVALID_ADDRESS
	res = OnNewConnection("passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:0", "policy-1", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 0)

	// L7 parser rejecting the connection based on connection metadata
	expected = FILTER_POLICY_DROP
	res = OnNewConnection("passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "invalid-policy", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 0)

	// Using test parser
	expected = FILTER_OK
	res = OnNewConnection("passer", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "policy-1", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 1)

	// 2nd connection
	origBuf2 := make([]byte, 0, 80)
	replyBuf2 := make([]byte, 0, 80)
	expected = FILTER_OK
	res = OnNewConnection("passer", 12345678901234567890, false, 2, 1, "2.2.2.2:80", "1.1.1.1:34567", "policy-2", &origBuf2, &replyBuf2)
	checkConnections(t, res, expected, 2)

	Close(1)
	checkConnections(t, res, expected, 1)

	Close(12345678901234567890)
	checkConnections(t, res, expected, 0)
}

type ExpFilterOp struct {
	op      FilterOpType
	n_bytes int
}

func checkOps(t *testing.T, ops []FilterOp, exp []ExpFilterOp) bool {
	t.Helper()
	if len(ops) != len(exp) {
		return false
	} else {
		for i, op := range ops {
			if op.op != uint32(exp[i].op) || op.n_bytes != uint32(exp[i].n_bytes) {
				return false
			}
		}
	}
	return true
}

func checkOnData(t *testing.T, res, expected FilterResult, ops []FilterOp, expOps []ExpFilterOp) {
	t.Helper()
	if res != expected {
		t.Errorf("OnData(): Invalid result, have %s, expected %s", res.String(), expected.String())
	}
	if !checkOps(t, ops, expOps) {
		t.Errorf("OnData(): Unexpected filter operations: %v, expected %v", ops, expOps)
	}
}

func checkBuf(t *testing.T, buf []byte, expected string) {
	if len(buf) < len(expected) {
		t.Log("Inject buffer too small, data truncated")
		expected = expected[:len(buf)] // truncate to buffer length
	}
	if string(buf) != expected {
		t.Errorf("OnData(): Expected inject buffer to be %s, buf have: %s", expected, buf)
	}
}

func checkAccessLogs(t *testing.T, logServer *accessLogServer, expPasses, expDrops int) bool {
	t.Helper()
	passes, drops := 0, 0
	empty := false
	for !empty {
		select {
		case pblog := <-logServer.logs:
			if pblog.EntryType == cilium.EntryType_Denied {
				drops++
			} else {
				passes++
			}
		case <-time.After(10 * time.Millisecond):
			empty = true
		}
	}
	return passes == expPasses && drops == expDrops
}

func TestOnDataNoPolicy(t *testing.T) {
	logServer := startAccessLogServer(t, "access_log.sock")
	defer logServer.close()

	if !InitModule(logServer.path) {
		t.Errorf("InitModule() with access log path %s failed", logServer.path)
	}

	origBuf := make([]byte, 0, 30)
	replyBuf := make([]byte, 1, 30)
	replyBufAddr := &replyBuf[0]
	replyBuf = replyBuf[:0] // make the buffer empty again

	// Using headertester parser
	expected := FILTER_OK
	res := OnNewConnection("headertester", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "policy-1", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 1)

	// Original direction data, drops with remaining data
	expected = FILTER_OK
	line1, line2, line3 := "No policy\n", "Dropped\n", "foo"
	data := line1 + line2 + line3
	ops := make([]FilterOp, 0, 10)
	expOps := []ExpFilterOp{
		{FILTEROP_DROP, len(line1)},
		{FILTEROP_DROP, len(line2)},
		{FILTEROP_MORE, 1},
	}
	res = OnData(1, false, false, &[]string{data}, &ops)
	checkOnData(t, res, expected, ops, expOps)
	checkBuf(t, replyBuf, "Line dropped: "+line1+"Line dropped: "+line2)

	if replyBufAddr != &replyBuf[0] {
		t.Error("OnData(): Reply injection buffer reallocated while it must not be!")
	}
	replyBuf = replyBuf[:0] // make the buffer empty again

	// No new input
	ops = ops[:0] // make empty
	expected = FILTER_OK
	expOps = []ExpFilterOp{
		{FILTEROP_MORE, 1},
	}
	res = OnData(1, false, false, &[]string{line3}, &ops)
	checkOnData(t, res, expected, ops, expOps)

	// Empty
	ops = ops[:0] // make empty
	expected = FILTER_OK
	expOps = []ExpFilterOp{}
	res = OnData(1, false, false, &[]string{""}, &ops)
	checkOnData(t, res, expected, ops, expOps)

	expPasses, expDrops := 0, 2
	if !checkAccessLogs(t, logServer, expPasses, expDrops) {
		t.Errorf("OnData: Unexpected access log entries, expected %d passes and %d drops.", expPasses, expDrops)
	}
}

func insertPolicyText(t *testing.T, version string, policies []string) bool {
	typeUrl := "type.googleapis.com/cilium.NetworkPolicy"
	var resources []*any.Any

	for _, policy := range policies {
		pb := new(cilium.NetworkPolicy)
		err := proto.UnmarshalText(policy, pb)
		if err != nil {
			t.Errorf("Policy UnmarshalText failed: %v", err)
			return false
		}
		log.Infof("Text -> proto.Message: %s -> %v", policy, pb)
		data, err := proto.Marshal(pb)
		if err != nil {
			t.Errorf("Policy marshal failed: %v", err)
			return false
		}

		resources = append(resources, &any.Any{
			TypeUrl: typeUrl,
			Value:   data,
		})
	}

	msg := &envoy_api_v2.DiscoveryResponse{
		VersionInfo: version,
		Canary:      false,
		TypeUrl:     typeUrl,
		Nonce:       "randomNonce1",
		Resources:   resources,
	}
	err := policyMap.Update(msg)
	if err != nil {
		t.Errorf("Policy Update failed: %v", err)
		return false
	}
	return true
}

func TestSimplePolicy(t *testing.T) {
	logServer := startAccessLogServer(t, "access_log.sock")
	defer logServer.close()

	if !InitModule(logServer.path) {
		t.Errorf("InitModule() with access log path %s failed", logServer.path)
	}

	insertPolicyText(t, "1", []string{`
		name: "FooBar"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    http_rules: <
		      http_rules: <
		        headers: <
		          name: "from"
		          exact_match: "someone"
		        >
		      >
		      http_rules: <
		        headers: <
		          name: "to"
		          exact_match: "else"
		        >
		      >
		    >
		  >
		>
		`})

	origBuf := make([]byte, 0, 256)
	replyBuf := make([]byte, 1, 256)
	replyBuf = replyBuf[:0] // make the buffer empty again

	// Using headertester parser
	expected := FILTER_OK
	res := OnNewConnection("headertester", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "FooBar", &origBuf, &replyBuf)
	checkConnections(t, res, expected, 1)

	// Original direction data, drops with remaining data
	expected = FILTER_OK
	line1, line2, line3, line4 := "from=someone\n", "foo\n", "to=else\n", "\n"
	data := line1 + line2 + line3 + line4
	ops := make([]FilterOp, 0, 10)
	expOps := []ExpFilterOp{
		{FILTEROP_PASS, len(line1)},
		{FILTEROP_DROP, len(line2)},
		{FILTEROP_PASS, len(line3)},
		{FILTEROP_DROP, len(line4)},
	}
	res = OnData(1, false, false, &[]string{data}, &ops)
	checkOnData(t, res, expected, ops, expOps)
	checkBuf(t, replyBuf, "Line dropped: "+line2+"Line dropped: "+line4)
	replyBuf = replyBuf[:0] // make the buffer empty again

	expPasses, expDrops := 2, 2
	if !checkAccessLogs(t, logServer, expPasses, expDrops) {
		t.Errorf("OnData: Unexpected access log entries, expected %d passes and %d drops.", expPasses, expDrops)
	}
}
