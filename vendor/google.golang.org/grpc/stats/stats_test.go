/*
 *
 * Copyright 2016, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package stats_test

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	testpb "google.golang.org/grpc/stats/grpc_testing"
)

func init() {
	grpc.EnableTracing = false
}

func TestStartStop(t *testing.T) {
	stats.RegisterRPCHandler(nil)
	stats.RegisterConnHandler(nil)
	stats.Start()
	if stats.On() {
		t.Fatalf("stats.Start() with nil handler, stats.On() = true, want false")
	}

	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {})
	stats.RegisterConnHandler(nil)
	stats.Start()
	if !stats.On() {
		t.Fatalf("stats.Start() with non-nil handler, stats.On() = false, want true")
	}
	stats.Stop()

	stats.RegisterRPCHandler(nil)
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {})
	stats.Start()
	if !stats.On() {
		t.Fatalf("stats.Start() with non-nil conn handler, stats.On() = false, want true")
	}
	stats.Stop()

	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {})
	if stats.On() {
		t.Fatalf("after stats.RegisterRPCHandler(), stats.On() = true, want false")
	}
	stats.Start()
	if !stats.On() {
		t.Fatalf("after stats.Start(_), stats.On() = false, want true")
	}

	stats.Stop()
	if stats.On() {
		t.Fatalf("after stats.Stop(), stats.On() = true, want false")
	}
}

type connCtxKey struct{}
type rpcCtxKey struct{}

func TestTagConnCtx(t *testing.T) {
	defer stats.RegisterConnTagger(nil)
	ctx1 := context.Background()
	stats.RegisterConnTagger(nil)
	ctx2 := stats.TagConn(ctx1, nil)
	if ctx2 != ctx1 {
		t.Fatalf("nil conn ctx tagger should not modify context, got %v; want %v", ctx2, ctx1)
	}
	stats.RegisterConnTagger(func(ctx context.Context, info *stats.ConnTagInfo) context.Context {
		return context.WithValue(ctx, connCtxKey{}, "connctxvalue")
	})
	ctx3 := stats.TagConn(ctx1, nil)
	if v, ok := ctx3.Value(connCtxKey{}).(string); !ok || v != "connctxvalue" {
		t.Fatalf("got context %v; want %v", ctx3, context.WithValue(ctx1, connCtxKey{}, "connctxvalue"))
	}
}

func TestTagRPCCtx(t *testing.T) {
	defer stats.RegisterRPCTagger(nil)
	ctx1 := context.Background()
	stats.RegisterRPCTagger(nil)
	ctx2 := stats.TagRPC(ctx1, nil)
	if ctx2 != ctx1 {
		t.Fatalf("nil rpc ctx tagger should not modify context, got %v; want %v", ctx2, ctx1)
	}
	stats.RegisterRPCTagger(func(ctx context.Context, info *stats.RPCTagInfo) context.Context {
		return context.WithValue(ctx, rpcCtxKey{}, "rpcctxvalue")
	})
	ctx3 := stats.TagRPC(ctx1, nil)
	if v, ok := ctx3.Value(rpcCtxKey{}).(string); !ok || v != "rpcctxvalue" {
		t.Fatalf("got context %v; want %v", ctx3, context.WithValue(ctx1, rpcCtxKey{}, "rpcctxvalue"))
	}
}

var (
	// For headers:
	testMetadata = metadata.MD{
		"key1": []string{"value1"},
		"key2": []string{"value2"},
	}
	// For trailers:
	testTrailerMetadata = metadata.MD{
		"tkey1": []string{"trailerValue1"},
		"tkey2": []string{"trailerValue2"},
	}
	// The id for which the service handler should return error.
	errorID int32 = 32202
)

type testServer struct{}

func (s *testServer) UnaryCall(ctx context.Context, in *testpb.SimpleRequest) (*testpb.SimpleResponse, error) {
	md, ok := metadata.FromContext(ctx)
	if ok {
		if err := grpc.SendHeader(ctx, md); err != nil {
			return nil, grpc.Errorf(grpc.Code(err), "grpc.SendHeader(_, %v) = %v, want <nil>", md, err)
		}
		if err := grpc.SetTrailer(ctx, testTrailerMetadata); err != nil {
			return nil, grpc.Errorf(grpc.Code(err), "grpc.SetTrailer(_, %v) = %v, want <nil>", testTrailerMetadata, err)
		}
	}

	if in.Id == errorID {
		return nil, fmt.Errorf("got error id: %v", in.Id)
	}

	return &testpb.SimpleResponse{Id: in.Id}, nil
}

func (s *testServer) FullDuplexCall(stream testpb.TestService_FullDuplexCallServer) error {
	md, ok := metadata.FromContext(stream.Context())
	if ok {
		if err := stream.SendHeader(md); err != nil {
			return grpc.Errorf(grpc.Code(err), "%v.SendHeader(%v) = %v, want %v", stream, md, err, nil)
		}
		stream.SetTrailer(testTrailerMetadata)
	}
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			// read done.
			return nil
		}
		if err != nil {
			return err
		}

		if in.Id == errorID {
			return fmt.Errorf("got error id: %v", in.Id)
		}

		if err := stream.Send(&testpb.SimpleResponse{Id: in.Id}); err != nil {
			return err
		}
	}
}

// test is an end-to-end test. It should be created with the newTest
// func, modified as needed, and then started with its startServer method.
// It should be cleaned up with the tearDown method.
type test struct {
	t        *testing.T
	compress string

	ctx    context.Context // valid for life of test, before tearDown
	cancel context.CancelFunc

	testServer testpb.TestServiceServer // nil means none
	// srv and srvAddr are set once startServer is called.
	srv     *grpc.Server
	srvAddr string

	cc *grpc.ClientConn // nil until requested via clientConn
}

func (te *test) tearDown() {
	if te.cancel != nil {
		te.cancel()
		te.cancel = nil
	}
	if te.cc != nil {
		te.cc.Close()
		te.cc = nil
	}
	te.srv.Stop()
}

// newTest returns a new test using the provided testing.T and
// environment.  It is returned with default values. Tests should
// modify it before calling its startServer and clientConn methods.
func newTest(t *testing.T, compress string) *test {
	te := &test{t: t, compress: compress}
	te.ctx, te.cancel = context.WithCancel(context.Background())
	return te
}

// startServer starts a gRPC server listening. Callers should defer a
// call to te.tearDown to clean up.
func (te *test) startServer(ts testpb.TestServiceServer) {
	te.testServer = ts
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		te.t.Fatalf("Failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if te.compress == "gzip" {
		opts = append(opts,
			grpc.RPCCompressor(grpc.NewGZIPCompressor()),
			grpc.RPCDecompressor(grpc.NewGZIPDecompressor()),
		)
	}
	s := grpc.NewServer(opts...)
	te.srv = s
	if te.testServer != nil {
		testpb.RegisterTestServiceServer(s, te.testServer)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		te.t.Fatalf("Failed to parse listener address: %v", err)
	}
	addr := "127.0.0.1:" + port

	go s.Serve(lis)
	te.srvAddr = addr
}

func (te *test) clientConn() *grpc.ClientConn {
	if te.cc != nil {
		return te.cc
	}
	opts := []grpc.DialOption{grpc.WithInsecure()}
	if te.compress == "gzip" {
		opts = append(opts,
			grpc.WithCompressor(grpc.NewGZIPCompressor()),
			grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
		)
	}

	var err error
	te.cc, err = grpc.Dial(te.srvAddr, opts...)
	if err != nil {
		te.t.Fatalf("Dial(%q) = %v", te.srvAddr, err)
	}
	return te.cc
}

type rpcConfig struct {
	count    int  // Number of requests and responses for streaming RPCs.
	success  bool // Whether the RPC should succeed or return error.
	failfast bool
}

func (te *test) doUnaryCall(c *rpcConfig) (*testpb.SimpleRequest, *testpb.SimpleResponse, error) {
	var (
		resp *testpb.SimpleResponse
		req  *testpb.SimpleRequest
		err  error
	)
	tc := testpb.NewTestServiceClient(te.clientConn())
	if c.success {
		req = &testpb.SimpleRequest{Id: errorID + 1}
	} else {
		req = &testpb.SimpleRequest{Id: errorID}
	}
	ctx := metadata.NewContext(context.Background(), testMetadata)

	resp, err = tc.UnaryCall(ctx, req, grpc.FailFast(c.failfast))
	return req, resp, err
}

func (te *test) doFullDuplexCallRoundtrip(c *rpcConfig) ([]*testpb.SimpleRequest, []*testpb.SimpleResponse, error) {
	var (
		reqs  []*testpb.SimpleRequest
		resps []*testpb.SimpleResponse
		err   error
	)
	tc := testpb.NewTestServiceClient(te.clientConn())
	stream, err := tc.FullDuplexCall(metadata.NewContext(context.Background(), testMetadata), grpc.FailFast(c.failfast))
	if err != nil {
		return reqs, resps, err
	}
	var startID int32
	if !c.success {
		startID = errorID
	}
	for i := 0; i < c.count; i++ {
		req := &testpb.SimpleRequest{
			Id: int32(i) + startID,
		}
		reqs = append(reqs, req)
		if err = stream.Send(req); err != nil {
			return reqs, resps, err
		}
		var resp *testpb.SimpleResponse
		if resp, err = stream.Recv(); err != nil {
			return reqs, resps, err
		}
		resps = append(resps, resp)
	}
	if err = stream.CloseSend(); err != nil {
		return reqs, resps, err
	}
	if _, err = stream.Recv(); err != io.EOF {
		return reqs, resps, err
	}

	return reqs, resps, err
}

type expectedData struct {
	method      string
	serverAddr  string
	compression string
	reqIdx      int
	requests    []*testpb.SimpleRequest
	respIdx     int
	responses   []*testpb.SimpleResponse
	err         error
	failfast    bool
}

type gotData struct {
	ctx    context.Context
	client bool
	s      interface{} // This could be RPCStats or ConnStats.
}

const (
	begin int = iota
	end
	inPayload
	inHeader
	inTrailer
	outPayload
	outHeader
	outTrailer
	connbegin
	connend
)

func checkBegin(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.Begin
	)
	if st, ok = d.s.(*stats.Begin); !ok {
		t.Fatalf("got %T, want Begin", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	if st.BeginTime.IsZero() {
		t.Fatalf("st.BeginTime = %v, want <non-zero>", st.BeginTime)
	}
	if d.client {
		if st.FailFast != e.failfast {
			t.Fatalf("st.FailFast = %v, want %v", st.FailFast, e.failfast)
		}
	}
}

func checkInHeader(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.InHeader
	)
	if st, ok = d.s.(*stats.InHeader); !ok {
		t.Fatalf("got %T, want InHeader", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	// TODO check real length, not just > 0.
	if st.WireLength <= 0 {
		t.Fatalf("st.Lenght = 0, want > 0")
	}
	if !d.client {
		if st.FullMethod != e.method {
			t.Fatalf("st.FullMethod = %s, want %v", st.FullMethod, e.method)
		}
		if st.LocalAddr.String() != e.serverAddr {
			t.Fatalf("st.LocalAddr = %v, want %v", st.LocalAddr, e.serverAddr)
		}
		if st.Compression != e.compression {
			t.Fatalf("st.Compression = %v, want %v", st.Compression, e.compression)
		}

		if connInfo, ok := d.ctx.Value(connCtxKey{}).(*stats.ConnTagInfo); ok {
			if connInfo.RemoteAddr != st.RemoteAddr {
				t.Fatalf("connInfo.RemoteAddr = %v, want %v", connInfo.RemoteAddr, st.RemoteAddr)
			}
			if connInfo.LocalAddr != st.LocalAddr {
				t.Fatalf("connInfo.LocalAddr = %v, want %v", connInfo.LocalAddr, st.LocalAddr)
			}
		} else {
			t.Fatalf("got context %v, want one with connCtxKey", d.ctx)
		}
		if rpcInfo, ok := d.ctx.Value(rpcCtxKey{}).(*stats.RPCTagInfo); ok {
			if rpcInfo.FullMethodName != st.FullMethod {
				t.Fatalf("rpcInfo.FullMethod = %s, want %v", rpcInfo.FullMethodName, st.FullMethod)
			}
		} else {
			t.Fatalf("got context %v, want one with rpcCtxKey", d.ctx)
		}
	}
}

func checkInPayload(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.InPayload
	)
	if st, ok = d.s.(*stats.InPayload); !ok {
		t.Fatalf("got %T, want InPayload", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	if d.client {
		b, err := proto.Marshal(e.responses[e.respIdx])
		if err != nil {
			t.Fatalf("failed to marshal message: %v", err)
		}
		if reflect.TypeOf(st.Payload) != reflect.TypeOf(e.responses[e.respIdx]) {
			t.Fatalf("st.Payload = %T, want %T", st.Payload, e.responses[e.respIdx])
		}
		e.respIdx++
		if string(st.Data) != string(b) {
			t.Fatalf("st.Data = %v, want %v", st.Data, b)
		}
		if st.Length != len(b) {
			t.Fatalf("st.Lenght = %v, want %v", st.Length, len(b))
		}
	} else {
		b, err := proto.Marshal(e.requests[e.reqIdx])
		if err != nil {
			t.Fatalf("failed to marshal message: %v", err)
		}
		if reflect.TypeOf(st.Payload) != reflect.TypeOf(e.requests[e.reqIdx]) {
			t.Fatalf("st.Payload = %T, want %T", st.Payload, e.requests[e.reqIdx])
		}
		e.reqIdx++
		if string(st.Data) != string(b) {
			t.Fatalf("st.Data = %v, want %v", st.Data, b)
		}
		if st.Length != len(b) {
			t.Fatalf("st.Lenght = %v, want %v", st.Length, len(b))
		}
	}
	// TODO check WireLength and ReceivedTime.
	if st.RecvTime.IsZero() {
		t.Fatalf("st.ReceivedTime = %v, want <non-zero>", st.RecvTime)
	}
}

func checkInTrailer(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.InTrailer
	)
	if st, ok = d.s.(*stats.InTrailer); !ok {
		t.Fatalf("got %T, want InTrailer", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	// TODO check real length, not just > 0.
	if st.WireLength <= 0 {
		t.Fatalf("st.Lenght = 0, want > 0")
	}
}

func checkOutHeader(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.OutHeader
	)
	if st, ok = d.s.(*stats.OutHeader); !ok {
		t.Fatalf("got %T, want OutHeader", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	// TODO check real length, not just > 0.
	if st.WireLength <= 0 {
		t.Fatalf("st.Lenght = 0, want > 0")
	}
	if d.client {
		if st.FullMethod != e.method {
			t.Fatalf("st.FullMethod = %s, want %v", st.FullMethod, e.method)
		}
		if st.RemoteAddr.String() != e.serverAddr {
			t.Fatalf("st.RemoteAddr = %v, want %v", st.RemoteAddr, e.serverAddr)
		}
		if st.Compression != e.compression {
			t.Fatalf("st.Compression = %v, want %v", st.Compression, e.compression)
		}

		if rpcInfo, ok := d.ctx.Value(rpcCtxKey{}).(*stats.RPCTagInfo); ok {
			if rpcInfo.FullMethodName != st.FullMethod {
				t.Fatalf("rpcInfo.FullMethod = %s, want %v", rpcInfo.FullMethodName, st.FullMethod)
			}
		} else {
			t.Fatalf("got context %v, want one with rpcCtxKey", d.ctx)
		}
	}
}

func checkOutPayload(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.OutPayload
	)
	if st, ok = d.s.(*stats.OutPayload); !ok {
		t.Fatalf("got %T, want OutPayload", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	if d.client {
		b, err := proto.Marshal(e.requests[e.reqIdx])
		if err != nil {
			t.Fatalf("failed to marshal message: %v", err)
		}
		if reflect.TypeOf(st.Payload) != reflect.TypeOf(e.requests[e.reqIdx]) {
			t.Fatalf("st.Payload = %T, want %T", st.Payload, e.requests[e.reqIdx])
		}
		e.reqIdx++
		if string(st.Data) != string(b) {
			t.Fatalf("st.Data = %v, want %v", st.Data, b)
		}
		if st.Length != len(b) {
			t.Fatalf("st.Lenght = %v, want %v", st.Length, len(b))
		}
	} else {
		b, err := proto.Marshal(e.responses[e.respIdx])
		if err != nil {
			t.Fatalf("failed to marshal message: %v", err)
		}
		if reflect.TypeOf(st.Payload) != reflect.TypeOf(e.responses[e.respIdx]) {
			t.Fatalf("st.Payload = %T, want %T", st.Payload, e.responses[e.respIdx])
		}
		e.respIdx++
		if string(st.Data) != string(b) {
			t.Fatalf("st.Data = %v, want %v", st.Data, b)
		}
		if st.Length != len(b) {
			t.Fatalf("st.Lenght = %v, want %v", st.Length, len(b))
		}
	}
	// TODO check WireLength and ReceivedTime.
	if st.SentTime.IsZero() {
		t.Fatalf("st.SentTime = %v, want <non-zero>", st.SentTime)
	}
}

func checkOutTrailer(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.OutTrailer
	)
	if st, ok = d.s.(*stats.OutTrailer); !ok {
		t.Fatalf("got %T, want OutTrailer", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	if st.Client {
		t.Fatalf("st IsClient = true, want false")
	}
	// TODO check real length, not just > 0.
	if st.WireLength <= 0 {
		t.Fatalf("st.Lenght = 0, want > 0")
	}
}

func checkEnd(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.End
	)
	if st, ok = d.s.(*stats.End); !ok {
		t.Fatalf("got %T, want End", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	if st.EndTime.IsZero() {
		t.Fatalf("st.EndTime = %v, want <non-zero>", st.EndTime)
	}
	if grpc.Code(st.Error) != grpc.Code(e.err) || grpc.ErrorDesc(st.Error) != grpc.ErrorDesc(e.err) {
		t.Fatalf("st.Error = %v, want %v", st.Error, e.err)
	}
}

func checkConnBegin(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.ConnBegin
	)
	if st, ok = d.s.(*stats.ConnBegin); !ok {
		t.Fatalf("got %T, want ConnBegin", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	st.IsClient() // TODO remove this.
}

func checkConnEnd(t *testing.T, d *gotData, e *expectedData) {
	var (
		ok bool
		st *stats.ConnEnd
	)
	if st, ok = d.s.(*stats.ConnEnd); !ok {
		t.Fatalf("got %T, want ConnEnd", d.s)
	}
	if d.ctx == nil {
		t.Fatalf("d.ctx = nil, want <non-nil>")
	}
	st.IsClient() // TODO remove this.
}

func tagConnCtx(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return context.WithValue(ctx, connCtxKey{}, info)
}

func tagRPCCtx(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, rpcCtxKey{}, info)
}

func checkServerStats(t *testing.T, got []*gotData, expect *expectedData, checkFuncs []func(t *testing.T, d *gotData, e *expectedData)) {
	if len(got) != len(checkFuncs) {
		t.Fatalf("got %v stats, want %v stats", len(got), len(checkFuncs))
	}

	var (
		rpcctx  context.Context
		connctx context.Context
	)
	for i := 0; i < len(got); i++ {
		if _, ok := got[i].s.(stats.RPCStats); ok {
			if rpcctx != nil && got[i].ctx != rpcctx {
				t.Fatalf("got different contexts with stats %T", got[i].s)
			}
			rpcctx = got[i].ctx
		} else {
			if connctx != nil && got[i].ctx != connctx {
				t.Fatalf("got different contexts with stats %T", got[i].s)
			}
			connctx = got[i].ctx
		}
	}

	for i, f := range checkFuncs {
		f(t, got[i], expect)
	}
}

func TestServerStatsUnaryRPC(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "")
	te.startServer(&testServer{})
	defer te.tearDown()

	req, resp, err := te.doUnaryCall(&rpcConfig{success: true})
	if err != nil {
		t.Fatalf(err.Error())
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:     "/grpc.testing.TestService/UnaryCall",
		serverAddr: te.srvAddr,
		requests:   []*testpb.SimpleRequest{req},
		responses:  []*testpb.SimpleResponse{resp},
	}

	checkFuncs := []func(t *testing.T, d *gotData, e *expectedData){
		checkConnBegin,
		checkInHeader,
		checkBegin,
		checkInPayload,
		checkOutHeader,
		checkOutPayload,
		checkOutTrailer,
		checkEnd,
		checkConnEnd,
	}

	checkServerStats(t, got, expect, checkFuncs)
}

func TestServerStatsUnaryRPCError(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "")
	te.startServer(&testServer{})
	defer te.tearDown()

	req, resp, err := te.doUnaryCall(&rpcConfig{success: false})
	if err == nil {
		t.Fatalf("got error <nil>; want <non-nil>")
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:     "/grpc.testing.TestService/UnaryCall",
		serverAddr: te.srvAddr,
		requests:   []*testpb.SimpleRequest{req},
		responses:  []*testpb.SimpleResponse{resp},
		err:        err,
	}

	checkFuncs := []func(t *testing.T, d *gotData, e *expectedData){
		checkConnBegin,
		checkInHeader,
		checkBegin,
		checkInPayload,
		checkOutHeader,
		checkOutTrailer,
		checkEnd,
		checkConnEnd,
	}

	checkServerStats(t, got, expect, checkFuncs)
}

func TestServerStatsStreamingRPC(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "gzip")
	te.startServer(&testServer{})
	defer te.tearDown()

	count := 5
	reqs, resps, err := te.doFullDuplexCallRoundtrip(&rpcConfig{count: count, success: true})
	if err == nil {
		t.Fatalf(err.Error())
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:      "/grpc.testing.TestService/FullDuplexCall",
		serverAddr:  te.srvAddr,
		compression: "gzip",
		requests:    reqs,
		responses:   resps,
	}

	checkFuncs := []func(t *testing.T, d *gotData, e *expectedData){
		checkConnBegin,
		checkInHeader,
		checkBegin,
		checkOutHeader,
	}
	ioPayFuncs := []func(t *testing.T, d *gotData, e *expectedData){
		checkInPayload,
		checkOutPayload,
	}
	for i := 0; i < count; i++ {
		checkFuncs = append(checkFuncs, ioPayFuncs...)
	}
	checkFuncs = append(checkFuncs,
		checkOutTrailer,
		checkEnd,
		checkConnEnd,
	)

	checkServerStats(t, got, expect, checkFuncs)
}

func TestServerStatsStreamingRPCError(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if !s.IsClient() {
			got = append(got, &gotData{ctx, false, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "gzip")
	te.startServer(&testServer{})
	defer te.tearDown()

	count := 5
	reqs, resps, err := te.doFullDuplexCallRoundtrip(&rpcConfig{count: count, success: false})
	if err == nil {
		t.Fatalf("got error <nil>; want <non-nil>")
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:      "/grpc.testing.TestService/FullDuplexCall",
		serverAddr:  te.srvAddr,
		compression: "gzip",
		requests:    reqs,
		responses:   resps,
		err:         err,
	}

	checkFuncs := []func(t *testing.T, d *gotData, e *expectedData){
		checkConnBegin,
		checkInHeader,
		checkBegin,
		checkOutHeader,
		checkInPayload,
		checkOutTrailer,
		checkEnd,
		checkConnEnd,
	}

	checkServerStats(t, got, expect, checkFuncs)
}

type checkFuncWithCount struct {
	f func(t *testing.T, d *gotData, e *expectedData)
	c int // expected count
}

func checkClientStats(t *testing.T, got []*gotData, expect *expectedData, checkFuncs map[int]*checkFuncWithCount) {
	var expectLen int
	for _, v := range checkFuncs {
		expectLen += v.c
	}
	if len(got) != expectLen {
		t.Fatalf("got %v stats, want %v stats", len(got), expectLen)
	}

	var (
		rpcctx  context.Context
		connctx context.Context
	)
	for i := 0; i < len(got); i++ {
		if _, ok := got[i].s.(stats.RPCStats); ok {
			if rpcctx != nil && got[i].ctx != rpcctx {
				t.Fatalf("got different contexts with stats %T", got[i].s)
			}
			rpcctx = got[i].ctx
		} else {
			if connctx != nil && got[i].ctx != connctx {
				t.Fatalf("got different contexts with stats %T", got[i].s)
			}
			connctx = got[i].ctx
		}
	}

	for _, s := range got {
		switch s.s.(type) {
		case *stats.Begin:
			if checkFuncs[begin].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[begin].f(t, s, expect)
			checkFuncs[begin].c--
		case *stats.OutHeader:
			if checkFuncs[outHeader].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[outHeader].f(t, s, expect)
			checkFuncs[outHeader].c--
		case *stats.OutPayload:
			if checkFuncs[outPayload].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[outPayload].f(t, s, expect)
			checkFuncs[outPayload].c--
		case *stats.InHeader:
			if checkFuncs[inHeader].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[inHeader].f(t, s, expect)
			checkFuncs[inHeader].c--
		case *stats.InPayload:
			if checkFuncs[inPayload].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[inPayload].f(t, s, expect)
			checkFuncs[inPayload].c--
		case *stats.InTrailer:
			if checkFuncs[inTrailer].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[inTrailer].f(t, s, expect)
			checkFuncs[inTrailer].c--
		case *stats.End:
			if checkFuncs[end].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[end].f(t, s, expect)
			checkFuncs[end].c--
		case *stats.ConnBegin:
			if checkFuncs[connbegin].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[connbegin].f(t, s, expect)
			checkFuncs[connbegin].c--
		case *stats.ConnEnd:
			if checkFuncs[connend].c <= 0 {
				t.Fatalf("unexpected stats: %T", s.s)
			}
			checkFuncs[connend].f(t, s, expect)
			checkFuncs[connend].c--
		default:
			t.Fatalf("unexpected stats: %T", s.s)
		}
	}
}

func TestClientStatsUnaryRPC(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "")
	te.startServer(&testServer{})
	defer te.tearDown()

	failfast := false
	req, resp, err := te.doUnaryCall(&rpcConfig{success: true, failfast: failfast})
	if err != nil {
		t.Fatalf(err.Error())
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:     "/grpc.testing.TestService/UnaryCall",
		serverAddr: te.srvAddr,
		requests:   []*testpb.SimpleRequest{req},
		responses:  []*testpb.SimpleResponse{resp},
		failfast:   failfast,
	}

	checkFuncs := map[int]*checkFuncWithCount{
		connbegin:  {checkConnBegin, 1},
		begin:      {checkBegin, 1},
		outHeader:  {checkOutHeader, 1},
		outPayload: {checkOutPayload, 1},
		inHeader:   {checkInHeader, 1},
		inPayload:  {checkInPayload, 1},
		inTrailer:  {checkInTrailer, 1},
		end:        {checkEnd, 1},
		connend:    {checkConnEnd, 1},
	}

	checkClientStats(t, got, expect, checkFuncs)
}

func TestClientStatsUnaryRPCError(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "")
	te.startServer(&testServer{})
	defer te.tearDown()

	failfast := true
	req, resp, err := te.doUnaryCall(&rpcConfig{success: false, failfast: failfast})
	if err == nil {
		t.Fatalf("got error <nil>; want <non-nil>")
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:     "/grpc.testing.TestService/UnaryCall",
		serverAddr: te.srvAddr,
		requests:   []*testpb.SimpleRequest{req},
		responses:  []*testpb.SimpleResponse{resp},
		err:        err,
		failfast:   failfast,
	}

	checkFuncs := map[int]*checkFuncWithCount{
		connbegin:  {checkConnBegin, 1},
		begin:      {checkBegin, 1},
		outHeader:  {checkOutHeader, 1},
		outPayload: {checkOutPayload, 1},
		inHeader:   {checkInHeader, 1},
		inTrailer:  {checkInTrailer, 1},
		end:        {checkEnd, 1},
		connend:    {checkConnEnd, 1},
	}

	checkClientStats(t, got, expect, checkFuncs)
}

func TestClientStatsStreamingRPC(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "gzip")
	te.startServer(&testServer{})
	defer te.tearDown()

	count := 5
	failfast := false
	reqs, resps, err := te.doFullDuplexCallRoundtrip(&rpcConfig{count: count, success: true, failfast: failfast})
	if err == nil {
		t.Fatalf(err.Error())
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:      "/grpc.testing.TestService/FullDuplexCall",
		serverAddr:  te.srvAddr,
		compression: "gzip",
		requests:    reqs,
		responses:   resps,
		failfast:    failfast,
	}

	checkFuncs := map[int]*checkFuncWithCount{
		connbegin:  {checkConnBegin, 1},
		begin:      {checkBegin, 1},
		outHeader:  {checkOutHeader, 1},
		outPayload: {checkOutPayload, count},
		inHeader:   {checkInHeader, 1},
		inPayload:  {checkInPayload, count},
		inTrailer:  {checkInTrailer, 1},
		end:        {checkEnd, 1},
		connend:    {checkConnEnd, 1},
	}

	checkClientStats(t, got, expect, checkFuncs)
}

func TestClientStatsStreamingRPCError(t *testing.T) {
	var (
		mu  sync.Mutex
		got []*gotData
	)
	stats.RegisterRPCHandler(func(ctx context.Context, s stats.RPCStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnHandler(func(ctx context.Context, s stats.ConnStats) {
		mu.Lock()
		defer mu.Unlock()
		if s.IsClient() {
			got = append(got, &gotData{ctx, true, s})
		}
	})
	stats.RegisterConnTagger(tagConnCtx)
	stats.RegisterRPCTagger(tagRPCCtx)
	stats.Start()
	defer stats.Stop()

	te := newTest(t, "gzip")
	te.startServer(&testServer{})
	defer te.tearDown()

	count := 5
	failfast := true
	reqs, resps, err := te.doFullDuplexCallRoundtrip(&rpcConfig{count: count, success: false, failfast: failfast})
	if err == nil {
		t.Fatalf("got error <nil>; want <non-nil>")
	}
	te.srv.GracefulStop() // Wait for the server to stop.

	expect := &expectedData{
		method:      "/grpc.testing.TestService/FullDuplexCall",
		serverAddr:  te.srvAddr,
		compression: "gzip",
		requests:    reqs,
		responses:   resps,
		err:         err,
		failfast:    failfast,
	}

	checkFuncs := map[int]*checkFuncWithCount{
		connbegin:  {checkConnBegin, 1},
		begin:      {checkBegin, 1},
		outHeader:  {checkOutHeader, 1},
		outPayload: {checkOutPayload, 1},
		inHeader:   {checkInHeader, 1},
		inTrailer:  {checkInTrailer, 1},
		end:        {checkEnd, 1},
		connend:    {checkConnEnd, 1},
	}

	checkClientStats(t, got, expect, checkFuncs)
}
