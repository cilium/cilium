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
	"fmt"
	"testing"

	_ "gopkg.in/check.v1"

	textmemcache "github.com/cilium/cilium/proxylib/memcached/text"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
)

var setHelloText = []byte("set key 0 0 5\r\nhello\r\n")
var setHelloTextNoreply = []byte("set key 0 0 5 noreply\r\nhello\r\n")

var getKeysText = []byte("get key1 key2 key3\r\n")
var gatKeysText = []byte("gat 5 key1 key2 key3\r\n")
var getResponse = []byte(
	"VALUE key3 0 4\r\n" +
		"xDDD\r\n" +
		"VALUE key4 0 3\r\n" +
		"xDD\r\n" +
		"END\r\n")

var deleteText = []byte("delete key\r\n")
var incrText = []byte("incr key 5\r\n")
var touchText = []byte("touch key 55\r\n")
var slabsText = []byte("slabs automove 1\r\n")
var okText = []byte("OK\r\n")
var lruCrawlerText = []byte("lru_crawler metadump all\r\n")
var statsText = []byte("stats\r\n")
var flushAllText = []byte("flush_all 15\r\n")

var lruCrawlerResponse = []byte(
	"key=key3 exp=1538047402 la=1538046902 cas=1 fetch=no cls=1 size=67\r\n" +
		"key=key4 exp=1538047402 la=1538046902 cas=2 fetch=no cls=1 size=66\r\n" +
		"END\r\n")

var statsResponse = []byte(
	"STAT evictions 0\r\n" +
		"STAT reclaimed 2\r\n" +
		"STAT crawler_reclaimed\r\n" +
		"STAT crawler_items_checked 18\r\n" +
		"STAT lrutail_reflocked 0\r\n" +
		"STAT moves_to_cold 6\r\n" +
		"STAT moves_to_warm 0\r\n" +
		"STAT moves_within_lru 0\r\n" +
		"STAT direct_reclaims 0\r\n" +
		"STAT lru_bumps_dropped 0\r\n" +
		"END\r\n")

var notFound = []byte("NOT_FOUND\r\n")

var stored = []byte("STORED\r\n")

var testCases = []testCase{
	{
		"set pass",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "set"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{setHelloText}, []ExpFilterOp{
				{proxylib.PASS, len(setHelloText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{stored}, []ExpFilterOp{
				{proxylib.PASS, len(stored)},
			}, proxylib.OK, "")
		},
	},
	{
		"set drop",
		`		        rule: <
		          key: "keyExact"
		          value: "trolo"
				>
				rule: <
				  key: "command"
				  value: "set"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{setHelloText}, []ExpFilterOp{
				{proxylib.DROP, len(setHelloText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"get pass",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "get"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{getKeysText, getKeysText}, []ExpFilterOp{
				{proxylib.PASS, len(getKeysText)}, {proxylib.PASS, len(getKeysText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{getResponse, getResponse}, []ExpFilterOp{
				{proxylib.PASS, len(getResponse)}, {proxylib.PASS, len(getResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"get more",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "get"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{getResponse[:5]}, []ExpFilterOp{
				{proxylib.MORE, 1},
			}, proxylib.OK, "")
		},
	},
	{
		"get drop",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "set"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{getKeysText}, []ExpFilterOp{
				{proxylib.DROP, len(getKeysText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"gat pass",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "gat"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{gatKeysText, gatKeysText}, []ExpFilterOp{
				{proxylib.PASS, len(gatKeysText)}, {proxylib.PASS, len(gatKeysText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{getResponse, getResponse}, []ExpFilterOp{
				{proxylib.PASS, len(getResponse)}, {proxylib.PASS, len(getResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"gat more",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "gat"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{getResponse[:5]}, []ExpFilterOp{
				{proxylib.MORE, 1},
			}, proxylib.OK, "")
		},
	},
	{
		"gat drop",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "set"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{gatKeysText}, []ExpFilterOp{
				{proxylib.DROP, len(gatKeysText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"delete pass",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "delete"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{deleteText}, []ExpFilterOp{
				{proxylib.PASS, len(deleteText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{notFound}, []ExpFilterOp{
				{proxylib.PASS, len(notFound)},
			}, proxylib.OK, "")
		},
	},
	{
		"delete drop",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "set"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{deleteText}, []ExpFilterOp{
				{proxylib.DROP, len(deleteText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"incr pass",
		`		        rule: <
		          key: "keyExact"
		          value: ""
				>
				rule: <
				  key: "command"
				  value: "incr"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{incrText}, []ExpFilterOp{
				{proxylib.PASS, len(incrText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{notFound}, []ExpFilterOp{
				{proxylib.PASS, len(notFound)},
			}, proxylib.OK, "")
		},
	},
	{
		"incr drop",
		`		        rule: <
		          key: "keyExact"
		          value: "otherKey"
				>
				rule: <
				  key: "command"
				  value: "incr"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{incrText}, []ExpFilterOp{
				{proxylib.DROP, len(incrText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"touch pass",
		`		        rule: <
		          key: "keyExact"
		          value: "key"
				>
				rule: <
				  key: "command"
				  value: "touch"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{touchText}, []ExpFilterOp{
				{proxylib.PASS, len(touchText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{notFound}, []ExpFilterOp{
				{proxylib.PASS, len(notFound)},
			}, proxylib.OK, "")
		},
	},
	{
		"touch drop",
		`		        rule: <
		          key: "keyExact"
		          value: "otherKey"
				>
				rule: <
				  key: "command"
				  value: "touch"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{touchText}, []ExpFilterOp{
				{proxylib.DROP, len(touchText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"slabs pass",
		`		        rule: <
				  key: "command"
				  value: "slabs"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{slabsText}, []ExpFilterOp{
				{proxylib.PASS, len(slabsText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{okText}, []ExpFilterOp{
				{proxylib.PASS, len(okText)},
			}, proxylib.OK, "")
		},
	},
	{
		"slabs drop",
		`		        rule: <
		          key: "keyExact"
		          value: "otherKey"
				>
				rule: <
				  key: "command"
				  value: "touch"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{slabsText}, []ExpFilterOp{
				{proxylib.DROP, len(slabsText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"lru_crawler response req more and pass",
		`		        rule: <
				  key: "command"
				  value: "lru_crawler"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{lruCrawlerText}, []ExpFilterOp{
				{proxylib.PASS, len(lruCrawlerText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{lruCrawlerResponse[:5]}, []ExpFilterOp{
				{proxylib.MORE, 1},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{lruCrawlerResponse}, []ExpFilterOp{
				{proxylib.PASS, len(lruCrawlerResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"stats response req more and pass",
		`		        rule: <
				  key: "command"
				  value: "stats"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{statsText}, []ExpFilterOp{
				{proxylib.PASS, len(statsText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{statsResponse[:5]}, []ExpFilterOp{
				{proxylib.MORE, 1},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{statsResponse}, []ExpFilterOp{
				{proxylib.PASS, len(statsResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"flush_all pass",
		`		        rule: <
				  key: "command"
				  value: "flush_all"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{flushAllText}, []ExpFilterOp{
				{proxylib.PASS, len(flushAllText)}, {proxylib.MORE, 1},
			}, proxylib.OK, "")

		},
	},
	{
		"flush_all denied",
		`		        rule: <
				  key: "command"
				  value: "get"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{flushAllText}, []ExpFilterOp{
				{proxylib.DROP, len(flushAllText)}, {proxylib.MORE, 1},
			}, proxylib.OK, string(textmemcache.DeniedMsg))

		},
	},
}

func TestTextMemcache(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			logServer := test.StartAccessLogServer(t, "access_log.sock", 10)
			defer logServer.Close()

			mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
			if mod == 0 {
				t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
			} else {
				defer CloseModule(mod)
			}

			insertPolicyText(t, mod, "1", []string{fmt.Sprintf(`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "textmemcache"
		    l7_rules: <
		      l7_rules: <
%s
		      >
		    >
		  >
		>
		`, tc.policy)})

			buf := CheckOnNewConnection(t, mod, "textmemcache", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1",
				30, proxylib.OK, 1)

			tc.onDataChecks(t)

			CheckClose(t, 1, buf, 1)
		})
	}
}

type testCase struct {
	name         string
	policy       string
	onDataChecks func(*testing.T)
}
