// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/dns"
	"golang.org/x/net/nettest"
	"golang.org/x/sync/errgroup"
)

var (
	clients = NewSharedClients()
)

func TestSharedClientSync(t *testing.T) {
	dns.HandleFunc("miek.nl.", HelloServer)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeSOA)

	c, closer := clients.GetSharedClient("client-key", new(dns.Client), addrstr)
	defer closer()
	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	// And now another ExchangeAsync on the same shared client
	r, _, err = c.ExchangeShared(m)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r == nil || r.Rcode != dns.RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}

	// Now get the shared client again and make sure it is still the same client
	c2, closer2 := clients.GetSharedClient("client-key", new(dns.Client), addrstr)
	defer closer2()

	if c2 != c {
		t.Fatal("client not really shared")
	}
	m.Id = uint16(42)
	r, _, err = c2.ExchangeShared(m)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r == nil || r.Rcode != dns.RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}

func TestSharedClientConcurrentSync(t *testing.T) {
	dns.HandleFunc("miek.nl.", HelloServer)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	conf := &dns.Client{
		Timeout: 2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	eg, _ := errgroup.WithContext(ctx)
	f1 := func(id uint16) error {
		m := new(dns.Msg)
		m.SetQuestion("miek.nl.", dns.TypeSOA)
		m.Id = id

		c, closer := clients.GetSharedClient("concurrent-client", conf, addrstr)
		defer closer()
		r, _, err := c.ExchangeShared(m)
		if err != nil {
			return fmt.Errorf("%v: failed to exchange: %w", id, err)
		}
		if r == nil {
			return fmt.Errorf("%v: response is nil", id)
		}
		if r.Id != id {
			return fmt.Errorf("incorrect id (%d != %d)", r.Id, id)
		}
		if r.Rcode != dns.RcodeSuccess {
			return fmt.Errorf("%v: failed to get an valid answer\n%v", id, r)
		}
		return nil
	}

	// If we don't set a limit, it's possible that the 250 goroutines overwhelm the single read
	// goroutine to the point that the OS receive buffer fills up and we drop packets.
	eg.SetLimit(50)
	for id := uint16(1); id <= 250; id++ {
		eg.Go(func() error { return f1(id) })
	}
	err = eg.Wait()
	if err != nil {
		t.Errorf("failed: %v", err)
	}
}

// This tests that the shared client correctly handles multiple queries of
// differing size, such as queries which use EDNS0 to specify a larger size.
// This is tricky for the client to handle, since normally dns.Conn.UDPSize
// stores what size of buffer needs to be allocated, but in the shared client,
// this is shared between multiple goroutines/requests, which can have different
// sizes.
func TestSharedClientMixedSize(t *testing.T) {
	edns0ReplySent := make(chan struct{})
	handlerErrors := make(chan error, 4)

	dns.HandleFunc("miek.nl.", func(w dns.ResponseWriter, q *dns.Msg) {
		addEDNS0Reply := func(m *dns.Msg) {
			m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "miek.nl.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{strings.Repeat("A", 200)}}}
			m.Extra = []dns.RR{&dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.MaxMsgSize},
				Option: []dns.EDNS0{
					&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: strings.Repeat("A", 2000)},
				}}}
		}

		// Respond to the EDNS0 message first, but do so only after receiving
		// the smaller one.
		m := &dns.Msg{}
		m.SetReply(q)

		switch q.Id {
		case 1, 2:
			addEDNS0Reply(m)
			err := w.WriteMsg(m)
			if err != nil {
				handlerErrors <- fmt.Errorf("failed to send reply to first edns0 query: %w", err)
			}
			edns0ReplySent <- struct{}{}
		case 11, 12:
			<-edns0ReplySent
			err := w.WriteMsg(m)
			if err != nil {
				handlerErrors <- fmt.Errorf("failed to send reply to first normal query: %w", err)
			}
		default:
			handlerErrors <- fmt.Errorf("unexpected DNS message received: %v", q.String())
		}
	})
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	edns0Query := new(dns.Msg)
	edns0Query.SetQuestion("miek.nl.", dns.TypeTXT)
	// Tell the server we're prepared to accept a large message (UDP size passed in "Class" field in
	// EDNS0, see RFC 6891 6.1.2)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}}
	edns0Query.Extra = []dns.RR{o}
	edns0Query.Id = 1
	eq2 := edns0Query.Copy()
	eq2.Id = 2

	normalQuery := new(dns.Msg)
	normalQuery.SetQuestion("miek.nl.", dns.TypeSOA)
	normalQuery.Id = 11
	nq2 := normalQuery.Copy()
	nq2.Id = 12

	c, closer := clients.GetSharedClient("", &dns.Client{}, addrstr)
	defer closer()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// We manually set up a connection here so that we can wrap the underlying net.Conn without
	// racing the handler.
	conn, err := c.DialContext(ctx, c.serverAddr)
	if err != nil {
		t.Fatalf("failed to set up shared client conn: %v", err)
	}
	readingChan := make(chan struct{})
	conn.Conn = &connWrapper{
		conn.Conn.(net.PacketConn), // to ensure dns lib recognises this as a packetconn
		readingChan,
	}
	c.conn = conn
	c.wg.Add(1)
	go handler(&c.wg, c.Client, c.conn, c.requests, &c.udpSize)

	// Asynchronous so that the second message can be sent, on which the server synchronises.
	errSmallQuery := make(chan error)
	go func() {
		_, _, err := c.ExchangeSharedContext(ctx, normalQuery)
		errSmallQuery <- err
	}()
	<-readingChan

	// We expect both exchanges to fail initially, since reading the EDNS0 response fails parsing
	// since the buffer is not long enough. That triggers an error in the shared client, which then
	// errors out for all concurrent exchanges. We don't assert that they do fail, however, since
	// that is merely the behaviour of the current implementation - if they pass, that's great too.
	_, _, err = c.ExchangeSharedContext(ctx, edns0Query)
	if err != nil && !strings.Contains(err.Error(), "overflowing") {
		t.Errorf("failed to exchange first edns0 query with unexpected error: %v", err)
	}
	<-readingChan // drain another read

	if err := <-errSmallQuery; err != nil && !strings.Contains(err.Error(), "overflowing") {
		t.Errorf("failed to exchange first normal query with unexpected error: %v", err)
	}

	// Now, retry the exchanges now that the receive buffer size has been adapted - this simulates a
	// client retrying. This time, both exchanges should succeed.

	go func() {
		_, _, err := c.ExchangeSharedContext(ctx, nq2)
		errSmallQuery <- err
	}()

	<-readingChan
	_, _, err = c.ExchangeSharedContext(ctx, eq2)
	if err != nil {
		t.Errorf("failed to exchange second edns0 query: %v", err)
	}
	<-readingChan // drain another read

	if err := <-errSmallQuery; err != nil {
		t.Errorf("failed to exchange second normal query: %v", err)
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("failed to shutdown server: %v", err)
	}
	<-readingChan // drain final read

	close(handlerErrors)
	for err := range handlerErrors {
		t.Errorf("handler encountered error: %v", err)
	}
}

func TestSharedClientLocalAddress(t *testing.T) {
	dns.HandleFunc("miek.nl.", HelloServerEchoAddrPort)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeSOA)

	c, closer := clients.GetSharedClient("", new(dns.Client), addrstr)
	defer closer()

	c.Dialer = &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("0.0.0.0")}}

	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	laddr := c.conn.LocalAddr()
	if r == nil {
		t.Fatalf("No response")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	if len(r.Extra) != 1 {
		t.Fatalf("failed to get additional answers\n%v", r)
	}
	txt := r.Extra[0].(*dns.TXT)
	if txt == nil {
		t.Errorf("invalid TXT response\n%v", txt)
	}
	if len(txt.Txt) != 1 || !strings.Contains(txt.Txt[0], laddr.String()) {
		t.Errorf("invalid TXT response\n%v", txt.Txt)
	}
}

func TestSharedClientSyncBadID(t *testing.T) {
	dns.HandleFunc("miek.nl.", HelloServerBadID)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeSOA)

	// Test with client.Exchange, the plain Exchange function is just a wrapper, so
	// we don't need to test that separately.
	conf := &dns.Client{
		Timeout: 10 * time.Millisecond,
	}

	_, _, closer, err := clients.Exchange("", conf, m, addrstr)
	defer closer()

	if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("query did not time out")
	}
}

func TestSharedClientSyncBadThenGoodID(t *testing.T) {
	dns.HandleFunc("miek.nl.", HelloServerBadThenGoodID)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeSOA)

	r, _, closer, err := clients.ExchangeContext(context.TODO(), "", new(dns.Client), m, addrstr)
	defer closer()

	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatalf("No response")
	}
	if r.Id != m.Id {
		t.Errorf("failed to get response with expected Id")
	}
}

func TestSharedClientSyncTCPBadID(t *testing.T) {
	dns.HandleFunc("miek.nl.", HelloServerBadID)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeSOA)

	c, closer := clients.GetSharedClient("", new(dns.Client), addrstr)
	defer closer()

	c.Net = "tcp"
	c.Timeout = 10 * time.Millisecond

	// ExchangeShared does not pass through bad IDs, they will be filtered out just like
	// for UDP and the request should time out
	if _, _, err := c.ExchangeShared(m); err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("query did not time out")
	}
}

func TestSharedClientEDNS0(t *testing.T) {
	dns.HandleFunc("miek.nl.", HelloServer)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeDNSKEY)

	m.SetEdns0(2048, true)

	c, closer := clients.GetSharedClient("", new(dns.Client), addrstr)
	defer closer()

	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}

	if r != nil && r.Rcode != dns.RcodeSuccess {
		t.Errorf("failed to get a valid answer\n%v", r)
	}
}

// Validates the transmission and parsing of local dns.EDNS0 options.
func TestSharedClientEDNS0Local(t *testing.T) {
	optStr1 := "1979:0x0707"
	optStr2 := strconv.Itoa(dns.EDNS0LOCALSTART) + ":0x0601"

	handler := func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		m.Extra = make([]dns.RR, 1, 2)
		m.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"Hello local edns"}}

		// If the local options are what we expect, then reflect them back.
		ec1 := req.Extra[0].(*dns.OPT).Option[0].(*dns.EDNS0_LOCAL).String()
		ec2 := req.Extra[0].(*dns.OPT).Option[1].(*dns.EDNS0_LOCAL).String()
		if ec1 == optStr1 && ec2 == optStr2 {
			m.Extra = append(m.Extra, req.Extra[0])
		}

		w.WriteMsg(m)
	}

	dns.HandleFunc("miek.nl.", handler)
	defer dns.HandleRemove("miek.nl.")

	s, addrstr, err := runUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeTXT)

	// Add two local edns options to the query.
	ec1 := &dns.EDNS0_LOCAL{Code: 1979, Data: []byte{7, 7}}
	ec2 := &dns.EDNS0_LOCAL{Code: dns.EDNS0LOCALSTART, Data: []byte{6, 1}}
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}, Option: []dns.EDNS0{ec1, ec2}}
	m.Extra = append(m.Extra, o)

	c, closer := clients.GetSharedClient("", new(dns.Client), addrstr)
	defer closer()

	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %s", err)
	}

	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatal("failed to get a valid answer")
	}

	txt := r.Extra[0].(*dns.TXT).Txt[0]
	if txt != "Hello local edns" {
		t.Error("Unexpected result for miek.nl", txt, "!= Hello local edns")
	}

	// Validate the local options in the reply.
	got := r.Extra[1].(*dns.OPT).Option[0].(*dns.EDNS0_LOCAL).String()
	if got != optStr1 {
		t.Errorf("failed to get local edns0 answer; got %s, expected %s", got, optStr1)
	}

	got = r.Extra[1].(*dns.OPT).Option[1].(*dns.EDNS0_LOCAL).String()
	if got != optStr2 {
		t.Errorf("failed to get local edns0 answer; got %s, expected %s", got, optStr2)
	}
}

func TestSharedTimeout(t *testing.T) {
	// Set up a dummy UDP server that won't respond
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("unable to resolve local udp address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer conn.Close()
	addrstr := conn.LocalAddr().String()

	// Message to send
	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeTXT)

	runTest := func(name string, exchange func(m *dns.Msg, addr string, timeout time.Duration) (*dns.Msg, time.Duration, error)) {
		t.Run(name, func(t *testing.T) {
			start := time.Now()

			timeout := time.Millisecond
			// Need some more slack for the goroutines to close
			allowable := timeout + 50*time.Millisecond

			_, _, err := exchange(m, addrstr, timeout)
			if err == nil {
				t.Errorf("no timeout using dns.Client.%s", name)
			}

			length := time.Since(start)
			if length > allowable {
				t.Errorf("exchange took longer %v than specified Timeout %v", length, allowable)
			}
		})
	}
	runTest("ExchangeShared", func(m *dns.Msg, addr string, timeout time.Duration) (*dns.Msg, time.Duration, error) {
		c, closer := clients.GetSharedClient("", &dns.Client{Timeout: timeout}, addrstr)
		defer closer()

		return c.ExchangeShared(m)
	})
	runTest("ExchangeSharedContext", func(m *dns.Msg, addr string, timeout time.Duration) (*dns.Msg, time.Duration, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		c, closer := clients.GetSharedClient("", new(dns.Client), addrstr)
		defer closer()

		return c.ExchangeSharedContext(ctx, m)
	})
}

func HelloServer(w dns.ResponseWriter, q *dns.Msg) {
	r := &dns.Msg{}
	r.SetReply(q)

	r.Extra = make([]dns.RR, 1)
	r.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"Hello world"}}
	w.WriteMsg(r)
}

func HelloServerBadID(w dns.ResponseWriter, q *dns.Msg) {
	r := &dns.Msg{}
	r.SetReply(q)
	r.Id++

	r.Extra = make([]dns.RR, 1)
	r.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"Hello world"}}
	w.WriteMsg(r)
}

func HelloServerBadThenGoodID(w dns.ResponseWriter, q *dns.Msg) {
	r := &dns.Msg{}
	r.SetReply(q)
	r.Id++

	r.Extra = make([]dns.RR, 1)
	r.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"Hello world"}}
	w.WriteMsg(r)

	r.Id--
	w.WriteMsg(r)
}

func HelloServerEchoAddrPort(w dns.ResponseWriter, q *dns.Msg) {
	r := &dns.Msg{}
	r.SetReply(q)

	raddr := w.RemoteAddr().String()
	r.Extra = make([]dns.RR, 1)
	r.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{raddr}}
	w.WriteMsg(r)
}

func runUDPServer(addr string) (*dns.Server, string, error) {
	pc, err := nettest.NewLocalPacketListener("udp")
	if err != nil {
		return nil, "", fmt.Errorf("failed to udp listen: %w", err)
	}
	laddr := pc.LocalAddr().String()

	ready := make(chan error, 1)
	s := &dns.Server{
		PacketConn: pc,
		NotifyStartedFunc: func() {
			ready <- nil
		},
	}

	go func() {
		ready <- s.ActivateAndServe()
		pc.Close()
	}()

	// Wait until the server is ready.
	if err := <-ready; err != nil {
		return nil, "", err
	}
	return s, laddr, nil
}

func runTCPServer(addr string) (*dns.Server, string, error) {
	l, err := nettest.NewLocalListener("tcp")
	if err != nil {
		return nil, "", fmt.Errorf("failed to tcp listen: %w", err)
	}
	laddr := l.Addr().String()

	ready := make(chan error, 1)
	s := &dns.Server{
		Listener: l,
		NotifyStartedFunc: func() {
			ready <- nil
		},
	}

	go func() {
		ready <- s.ActivateAndServe()
		l.Close()
	}()

	// Wait until the server is ready.
	if err := <-ready; err != nil {
		return nil, "", err
	}
	return s, laddr, nil
}

type connWrapper struct {
	net.PacketConn // happens to also be a net.Conn

	reading chan struct{}
}

// Make connWrapper also implement net.Conn
func (c *connWrapper) Read(p []byte) (int, error) {
	c.reading <- struct{}{}
	return c.PacketConn.(net.Conn).Read(p)
}

func (c *connWrapper) Write(p []byte) (int, error) {
	return c.PacketConn.(net.Conn).Write(p)
}

func (c *connWrapper) RemoteAddr() net.Addr {
	return c.PacketConn.(net.Conn).RemoteAddr()
}
