// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package main

import (
	"fmt"
	"testing"

	_ "github.com/cilium/cilium/proxylib/memcached"
	binarymemcache "github.com/cilium/cilium/proxylib/memcached/binary"
	textmemcache "github.com/cilium/cilium/proxylib/memcached/text"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
)

var setHelloText = []byte("set key 0 0 5\r\nhello\r\n")

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
var watchText = []byte("watch mutations\r\n")

var watchReply = []byte(
	"OK\r\n" +
		"ts=1538135970.404892 gid=5 type=item_store key=key3 status=stored cmd=set ttl=500 clsid=1\r\n" +
		"ts=1538135970.404898 gid=6 type=item_store key=key4 status=stored cmd=set ttl=500 clsid=1\r\n" +
		"ts=1538135974.340708 gid=7 type=item_store key=key3 status=stored cmd=set ttl=500 clsid=1\r\n" +
		"ts=1538135974.340714 gid=8 type=item_store key=key4 status=stored cmd=set ttl=500 clsid=1\r\n" +
		"ts=1538135976.436863 gid=9 type=item_store key=key3 status=stored cmd=set ttl=500 clsid=1\r\n")

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

// binary packets
var getHello = []byte{
	128, 0, 0, 5,
	0, 0, 0, 0,
	0, 0, 0, 5,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'H', 'e', 'l', 'l',
	'o',
}

var getHelloResp = []byte{
	129, 0, 0, 0,
	4, 0, 0, 0,
	0, 0, 0, 9,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'W', 'o', 'r', 'l',
	'd',
}

var setHello = []byte{
	128, 1, 0, 5,
	8, 0, 0, 0,
	0, 0, 0, 18,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'H', 'e', 'l', 'l',
	'o', 'W', 'o', 'r',
	'l', 'd',
}

func TestMemcache(t *testing.T) {
	for _, tc := range append(textTestCases, binaryTestCases...) {
		t.Run(tc.name, func(t *testing.T) {

			logServer := test.StartAccessLogServer("access_log.sock", 10)
			defer logServer.Close()

			mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, false)
			if mod == 0 {
				t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
			} else {
				defer CloseModule(mod)
			}

			insertPolicyText(t, mod, "1", []string{fmt.Sprintf(`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "memcache"
		    l7_rules: <
		      l7_allow_rules: <
%s
		      >
		    >
		  >
		>
		`, tc.policy)})

			buf := CheckOnNewConnection(t, mod, "memcache", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
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

var textTestCases = []testCase{
	{
		"text set pass",
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
				{proxylib.PASS, len(setHelloText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{stored}, []ExpFilterOp{
				{proxylib.PASS, len(stored)},
			}, proxylib.OK, "")
		},
	},
	{
		"text set drop",
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
				{proxylib.DROP, len(setHelloText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"text get pass",
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
				{proxylib.PASS, len(getKeysText)}, {proxylib.PASS, len(getKeysText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{getResponse, getResponse}, []ExpFilterOp{
				{proxylib.PASS, len(getResponse)}, {proxylib.PASS, len(getResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"text get more",
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
				{proxylib.MORE, 2},
			}, proxylib.OK, "")
		},
	},
	{
		"text get drop",
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
				{proxylib.DROP, len(getKeysText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"text gat pass",
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
				{proxylib.PASS, len(gatKeysText)}, {proxylib.PASS, len(gatKeysText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{getResponse, getResponse}, []ExpFilterOp{
				{proxylib.PASS, len(getResponse)}, {proxylib.PASS, len(getResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"text gat more",
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
				{proxylib.MORE, 2},
			}, proxylib.OK, "")
		},
	},
	{
		"text gat drop",
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
				{proxylib.DROP, len(gatKeysText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"text delete pass",
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
				{proxylib.PASS, len(deleteText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{notFound}, []ExpFilterOp{
				{proxylib.PASS, len(notFound)},
			}, proxylib.OK, "")
		},
	},
	{
		"text delete drop",
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
				{proxylib.DROP, len(deleteText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"text incr pass",
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
				{proxylib.PASS, len(incrText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{notFound}, []ExpFilterOp{
				{proxylib.PASS, len(notFound)},
			}, proxylib.OK, "")
		},
	},
	{
		"text incr drop",
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
				{proxylib.DROP, len(incrText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"text touch pass",
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
				{proxylib.PASS, len(touchText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{notFound}, []ExpFilterOp{
				{proxylib.PASS, len(notFound)},
			}, proxylib.OK, "")
		},
	},
	{
		"text touch drop",
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
				{proxylib.DROP, len(touchText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"text slabs pass",
		`		        rule: <
				  key: "command"
				  value: "slabs"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{slabsText}, []ExpFilterOp{
				{proxylib.PASS, len(slabsText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{okText}, []ExpFilterOp{
				{proxylib.PASS, len(okText)},
			}, proxylib.OK, "")
		},
	},
	{
		"text slabs drop",
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
				{proxylib.DROP, len(slabsText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))
		},
	},
	{
		"text lru_crawler response req more and pass",
		`		        rule: <
				  key: "command"
				  value: "lru_crawler"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{lruCrawlerText}, []ExpFilterOp{
				{proxylib.PASS, len(lruCrawlerText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{lruCrawlerResponse[:5]}, []ExpFilterOp{
				{proxylib.MORE, 2},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{lruCrawlerResponse}, []ExpFilterOp{
				{proxylib.PASS, len(lruCrawlerResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"text stats response req more and pass",
		`		        rule: <
				  key: "command"
				  value: "stats"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{statsText}, []ExpFilterOp{
				{proxylib.PASS, len(statsText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{statsResponse[:5]}, []ExpFilterOp{
				{proxylib.MORE, 2},
			}, proxylib.OK, "")
			CheckOnData(t, 1, true, false, &[][]byte{statsResponse}, []ExpFilterOp{
				{proxylib.PASS, len(statsResponse)},
			}, proxylib.OK, "")
		},
	},
	{
		"text flush_all pass",
		`		        rule: <
				  key: "command"
				  value: "flush_all"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{flushAllText}, []ExpFilterOp{
				{proxylib.PASS, len(flushAllText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

		},
	},
	{
		"text flush_all denied",
		`		        rule: <
				  key: "command"
				  value: "get"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{flushAllText}, []ExpFilterOp{
				{proxylib.DROP, len(flushAllText)}, {proxylib.MORE, 2},
			}, proxylib.OK, string(textmemcache.DeniedMsg))

		},
	},
	{
		"text watch passed",
		`		        rule: <
				  key: "command"
				  value: "watch"
		        >
		`,
		func(t *testing.T) {

			CheckOnData(t, 1, false, false, &[][]byte{watchText}, []ExpFilterOp{
				{proxylib.PASS, len(watchText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{watchReply}, []ExpFilterOp{
				{proxylib.PASS, 4}, {proxylib.PASS, 91}, {proxylib.PASS, 91}, {proxylib.PASS, 91}, {proxylib.PASS, 91}, {proxylib.PASS, 91},
			}, proxylib.OK, "")
		},
	},
	{
		"text partial linefeed",
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

			CheckOnData(t, 1, false, false, &[][]byte{getKeysText[:len(getKeysText)-1]}, []ExpFilterOp{
				{proxylib.MORE, 1},
			}, proxylib.OK, "")
		},
	},
	{
		"text set pass on empty rule",
		"",
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{setHelloText}, []ExpFilterOp{
				{proxylib.PASS, len(setHelloText)}, {proxylib.MORE, 2},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{stored}, []ExpFilterOp{
				{proxylib.PASS, len(stored)},
			}, proxylib.OK, "")
		},
	},
}

var binaryTestCases = []testCase{
	{
		"bin get pass exact key",
		`		        rule: <
		          key: "keyExact"
		          value: "Hello"
				>
				rule: <
				  key: "command"
				  value: "get"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
				{proxylib.PASS, len(getHello)}, {proxylib.MORE, 24},
			}, proxylib.OK, "")
		},
	},
	{
		"bin get pass prefix key",
		`		        rule: <
		          key: "keyPrefix"
		          value: "Hell"
				>
				rule: <
				  key: "command"
				  value: "get"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
				{proxylib.PASS, len(getHello)}, {proxylib.MORE, 24},
			}, proxylib.OK, "")
		},
	},
	{
		"bin get pass regex key",
		`		        rule: <
		          key: "keyRegex"
		          value: "^.el.o$"
				>
				rule: <
				  key: "command"
				  value: "get"
		        >
		`,
		func(t *testing.T) {
			CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
				{proxylib.PASS, len(getHello)}, {proxylib.MORE, 24},
			}, proxylib.OK, "")
		},
	},
	{
		"bin get drop",
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
			CheckOnData(t, 1, false, false, &[][]byte{getHello}, []ExpFilterOp{
				{proxylib.DROP, len(getHello)}, {proxylib.MORE, 24},
			}, proxylib.OK, string(binarymemcache.DeniedMsgBase))
		},
	},
	{
		"bin get more",
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
			data := getHello[:10]
			CheckOnData(t, 1, false, false, &[][]byte{data}, []ExpFilterOp{{proxylib.MORE, 14}}, proxylib.OK, "")
		},
	},
	{
		"bin get split",
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
			data := getHello
			CheckOnData(t, 1, false, false, &[][]byte{data[:10], data[10:]}, []ExpFilterOp{
				{proxylib.PASS, len(data)}, {proxylib.MORE, 24},
			}, proxylib.OK, "")
		},
	},
	{
		"bin get remaining key",
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
			data := getHello[:26]
			CheckOnData(t, 1, false, false, &[][]byte{data}, []ExpFilterOp{
				{proxylib.MORE, 3},
			}, proxylib.OK, "")
		},
	},
	{
		"bin set drop and allow",
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
			CheckOnData(t, 1, false, false, &[][]byte{setHello, getHello}, []ExpFilterOp{
				{proxylib.PASS, len(setHello)}, {proxylib.DROP, len(getHello)}, {proxylib.MORE, 24},
			}, proxylib.OK, string(binarymemcache.DeniedMsgBase))

			CheckOnData(t, 1, true, false, &[][]byte{getHelloResp}, []ExpFilterOp{
				{proxylib.PASS, len(getHelloResp)}, {proxylib.INJECT, len(binarymemcache.DeniedMsgBase)},
			}, proxylib.OK, string(binarymemcache.DeniedMsgBase))
		},
	},
}
