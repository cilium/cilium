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

import (
	//	"path/filepath"
	"encoding/hex"
	"testing"

	_ "gopkg.in/check.v1"

	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
	_ "github.com/cilium/cilium/proxylib/testparsers"

	log "github.com/sirupsen/logrus"
)


// util function used for Cassandra tests, as we have cassandra requests
// as hex strings
func hex_to_str(data_hex []byte) string {
	data_raw := make([]byte, hex.DecodedLen(len(data_hex)))
	_, err := hex.Decode(data_raw, data_hex)
	if err != nil {
		log.Fatal(err)
	}
	return string(data_raw)
}

func TestCassandraOnDataNoHeader(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "cp7"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "query_table"
		          value: ".*"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, "cassandra", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp7",
		30, proxylib.OK, 1)

	data1 := hex_to_str([]byte("0400"))
	CheckOnData(t, 1, false, false, &[]string{data1}, []ExpFilterOp{
		{proxylib.MORE, 9 - len(data1)},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestCassandraOnDataOptionsReq(t *testing.T) {

	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "cp6"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "opcode"
		          value: "options"
                >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, "cassandra", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp6",
		30, proxylib.OK, 1)

	data2 := hex_to_str([]byte("040000000500000000"))
	CheckOnData(t, 1, false, false, &[]string{data2}, []ExpFilterOp{
		{proxylib.PASS, len(data2)}, {proxylib.MORE, 9},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

// this passes a large query request that is missing just the last byte
func TestCassandraOnDataPartialReq(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "cp5"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "query_table"
		          value: ".*"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, "cassandra", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp5",
		30, proxylib.OK, 1)

	data2 := hex_to_str([]byte("0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c270001"))
	CheckOnData(t, 1, false, false, &[]string{data2}, []ExpFilterOp{{proxylib.MORE, 1}}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestCassandraOnDataQueryReq(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "cp4"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "query_table"
		          value: ".*"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, "cassandra", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp4",
		30, proxylib.OK, 1)

	data2 := hex_to_str([]byte("0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100"))
	CheckOnData(t, 1, false, false, &[]string{data2}, []ExpFilterOp{
		{proxylib.PASS, len(data2)}, {proxylib.MORE, 9},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestCassandraOnDataSplitQueryReq(t *testing.T) {

	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "cp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "query_table"
		          value: ".*"
		        >
		      >
		    >
		  >
		>
		`})
	buf := CheckOnNewConnection(t, "cassandra", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp3",
		30, proxylib.OK, 1)

	data2 := hex_to_str([]byte("0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100"))
	CheckOnData(t, 1, false, false, &[]string{data2[:10], data2[10:]}, []ExpFilterOp{
		{proxylib.PASS, len(data2)}, {proxylib.MORE, 9},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestCassandraOnDataMultiReq(t *testing.T) {

	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "cp2"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "query_table"
		          value: ".*"
		        >
		      >
		    >
		  >
		>
		`})

	buf := CheckOnNewConnection(t, "cassandra", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp2",
		30, proxylib.OK, 1)

	data1 := hex_to_str([]byte("040000000500000000"))
	data2 := hex_to_str([]byte("0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100"))
	CheckOnData(t, 1, false, false, &[]string{data1 + data2}, []ExpFilterOp{
		{proxylib.PASS, len(data1)}, {proxylib.PASS, len(data2)}, {proxylib.MORE, 9},
	}, proxylib.OK, "")

	CheckClose(t, 1, buf, 1)
}

func TestSimpleCassandraPolicy(t *testing.T) {
	logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
	defer logServer.Close()

	if !InitModule([][2]string{{"access-log-path", logServer.Path}}, true) {
		t.Errorf("InitModule() with access log path %s failed", logServer.Path)
	}

	insertPolicyText(t, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "opcode"
		          value: "query"
                >
                rule: <
		          key: "query_table"
		          value: "system.local"
		        >
		      >
		    >
		  >
		>
		`})

	buf := CheckOnNewConnection(t, "cassandra", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1",
		80, proxylib.OK, 1)

	// FIXME: we should just grab this from the cassandra parser itself rather than duplicating here.
	unauth_msg_base := []byte{
		0x84,     // version (updated to have reply bit set and protocol version 4)
		0x0,      // flags, (uint8)
		0x0, 0x0, // stream-id (uint16) (test requests use zero as stream ID)
		0x0,                 // opcode error (uint8)
		0x0, 0x0, 0x0, 0x1a, // request length (uint32) - update if text changes
		0x0, 0x0, 0x21, 0x00, // 'unauthorized error code' 0x2100 (uint32)
		0x0, 0x14, // length of error msg (uint16)  - update if text changes
		'R', 'e', 'q', 'u', 'e', 's', 't', ' ', 'U', 'n', 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd',
	}

	data1 := hex_to_str([]byte("040000000500000000"))
	data2 := hex_to_str([]byte("0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100"))
	CheckOnData(t, 1, false, false, &[]string{data1 + data2}, []ExpFilterOp{
		{proxylib.DROP, len(data1)}, {proxylib.PASS, len(data2)}, {proxylib.MORE, 9},
	}, proxylib.OK, string(unauth_msg_base))

	expPasses, expDrops := 1, 1
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}
