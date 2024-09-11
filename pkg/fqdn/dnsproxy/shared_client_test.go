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

