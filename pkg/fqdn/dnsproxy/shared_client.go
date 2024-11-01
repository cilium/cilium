// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// SharedClients holds a set of SharedClient instances.
type SharedClients struct {
	// SharedClient's lock must not be taken while this lock is held!
	lock lock.Mutex
	// clients are created and destroyed on demand, hence 'Mutex' needs to be taken.
	clients map[string]*SharedClient
}

func NewSharedClients() *SharedClients {
	return &SharedClients{
		clients: make(map[string]*SharedClient),
	}
}

// sharedClientKey returns an identifier for this five-tuple used to find a shared client.
func sharedClientKey(protocol, client, server string) string {
	return protocol + "-" + client + "-" + server
}

func (s *SharedClients) Exchange(key string, conf *dns.Client, m *dns.Msg, serverAddrStr string) (r *dns.Msg, rtt time.Duration, closer func(), err error) {
	return s.ExchangeContext(context.Background(), key, conf, m, serverAddrStr)
}

func (s *SharedClients) ExchangeContext(ctx context.Context, key string, conf *dns.Client, m *dns.Msg, serverAddrStr string) (r *dns.Msg, rtt time.Duration, closer func(), err error) {
	client, closer := s.GetSharedClient(key, conf, serverAddrStr)
	r, rtt, err = client.ExchangeSharedContext(ctx, m)
	return r, rtt, closer, err
}

// Called by wrapped TCP connection once the downstream connection breaks/is
// closed. Used as a signal to close the upstream connection.
func (s *SharedClients) ShutdownTCPClient(key string) {
	// lock for s.clients access
	s.lock.Lock()
	client := s.clients[key]
	if client == nil {
		s.lock.Unlock()
		return
	}
	delete(s.clients, key)
	s.lock.Unlock()

	// The reference counting in the shared client is not authoritative for TCP.
	// It is increased on acquiring a reference to it, but never decreased,
	// since we don't want it to hit zero while the downstream connection is
	// open. Hence we also don't check for it being zero when closing.
	client.Lock()
	defer client.Unlock()
	client.close()
}

// GetSharedClient gets or creates an instance of SharedClient keyed with 'key'.  if 'key' is an
// empty sting, a new client is always created and it is not actually shared.  The returned 'closer'
// must be called once the client is no longer needed. Conversely, the returned 'client' must not be
// used after the closer is called.
func (s *SharedClients) GetSharedClient(key string, conf *dns.Client, serverAddrStr string) (client *SharedClient, closer func()) {
	if key == "" {
		// Simplified case when the client is actually not shared
		client = newSharedClient(conf, serverAddrStr)
		return client, client.close
	}
	for {
		// lock for s.clients access
		s.lock.Lock()
		// locate client to re-use if possible.
		client = s.clients[key]
		if client == nil {
			client = newSharedClient(conf, serverAddrStr)
			s.clients[key] = client
			s.lock.Unlock()
			// new client, we are done
			break
		}
		s.lock.Unlock()

		// reusing client that may start closing while we wait for its lock
		client.Lock()
		if client.refcount > 0 {
			// not closed, add our refcount
			client.refcount++
			client.Unlock()
			break
		}
		// client was closed while we waited for it's lock, discard and try again
		client.Unlock()
		client = nil
	}

	// TCP clients are cleaned up on downstream connection close.
	if conf.Net == "tcp" {
		return client, func() {}
	}

	return client, func() {
		client.Lock()
		defer client.Unlock()
		client.refcount--
		if client.refcount == 0 {
			// connection close must be completed while holding the client's lock to
			// avoid a race where a new client dials using the same 5-tuple and gets a
			// bind error.
			// The client remains findable so that new users with the same key may wait
			// for this closing to be done with.
			client.close()
			// Make client unreachable
			// Must take s.lock for this.
			s.lock.Lock()
			delete(s.clients, key)
			s.lock.Unlock()
		}
	}
}

type request struct {
	ctx context.Context
	msg *dns.Msg
	ch  chan sharedClientResponse
}

type sharedClientResponse struct {
	msg *dns.Msg
	rtt time.Duration
	err error
}

// A SharedClient keeps state for concurrent transactions on the same upstream client/connection.
type SharedClient struct {
	serverAddr string

	*dns.Client

	// requests is closed when the client needs to exit
	requests chan request
	// wg is waited on for the client finish exiting
	wg sync.WaitGroup
	// size of receive buffers to allocate, must only grow
	udpSize atomic.Uint32

	lock.Mutex // protects the fields below
	refcount   int
	conn       *dns.Conn
}

func newSharedClient(conf *dns.Client, serverAddr string) *SharedClient {
	return &SharedClient{
		refcount:   1,
		serverAddr: serverAddr,
		Client:     conf,
		requests:   make(chan request),
	}
}

// ExchangeShared dials a connection to the server on first invocation, and starts a handler
// goroutines to send and receive responses, distributing them to appropriate concurrent caller
// based on the DNS message Id.
func (c *SharedClient) ExchangeShared(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	return c.ExchangeSharedContext(context.Background(), m)
}

// handler is started when the connection is dialed
func handler(wg *sync.WaitGroup, client *dns.Client, conn *dns.Conn, requests chan request, size *atomic.Uint32) {
	defer wg.Done()

	responses := make(chan sharedClientResponse)

	// receiverTrigger is used to wake up the receive loop after request(s) have been sent. It
	// must be buffered to be able to send a trigger while the receive loop is not yet ready to
	// receive the trigger, as we do not want to stall the sender when the receiver is blocking
	// on the read operation.
	receiverTrigger := make(chan struct{}, 1)
	triggerReceiver := func() {
		select {
		case receiverTrigger <- struct{}{}:
		default:
		}
	}

	// Receive loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(responses)

		// Synthesize a dns.Conn for this reading goroutine, so that it is not
		// shared with the writing goroutines to placate the race detector.
		syntheticConn := dns.Conn{
			Conn: conn.Conn,
		}

		// No point trying to receive until the first request has been successfully sent, so
		// wait for a trigger first. receiverTrigger is buffered, so this is safe
		// to do, even if the sender sends the trigger before we are ready to receive here.
		<-receiverTrigger

		for {
			syntheticConn.UDPSize = uint16(size.Load())
			// This will block but eventually return an i/o timeout, as we always set
			// the timeouts before sending anything
			r, err := syntheticConn.ReadMsg()
			if err == nil {
				responses <- sharedClientResponse{r, 0, nil}
				continue // receive immediately again
			}

			// handler is not reading on the channel after closing.
			// UDP connections return net.ErrClosed, while TCP/TLS connections are read
			// via the io package, which return io.EOF.
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}

			// send error response to cancel all current requests.
			responses <- sharedClientResponse{nil, 0, err}

			// wait for a trigger from the handler after any errors. Re-reading in
			// this condition could busy loop, e.g., if a read timeout occurred.
			// receiverTrigger is buffered so that we catch the trigger that may
			// have been sent while we sent the error response above.
			_, ok := <-receiverTrigger
			if !ok {
				return // exit immediately when the trigger channel is closed
			}
		}
	}()

	type waiter struct {
		ch    chan sharedClientResponse
		start time.Time
	}
	waitingResponses := make(map[uint16]waiter)
	defer func() {
		conn.Close()
		close(receiverTrigger)

		// Drain responses send by receive loop to allow it to exit.
		// It may be repeatedly reading after an i/o timeout, for example.
		for range responses {
		}

		for _, waiter := range waitingResponses {
			waiter.ch <- sharedClientResponse{nil, 0, net.ErrClosed}
			close(waiter.ch)
		}
	}()

	for {
		select {
		case req, ok := <-requests:
			if !ok {
				// 'requests' is closed when SharedClient is recycled, which happens
				// responses (or errors) have been received and there are no more
				// requests to be sent.
				return
			}
			start := time.Now()

			// Check if we already have a request with the same id
			// Due to birthday paradox and the fact that ID is uint16
			// it's likely to happen with small number (~200) of concurrent requests
			// which would result in goroutine leak as we would never close req.ch
			if _, duplicate := waitingResponses[req.msg.Id]; duplicate {
				for n := 0; n < 5; n++ {
					// Try a new ID
					id := dns.Id()
					if _, duplicate = waitingResponses[id]; !duplicate {
						req.msg.Id = id
						break
					}
				}
				if duplicate {
					req.ch <- sharedClientResponse{nil, 0, fmt.Errorf("duplicate request id %d", req.msg.Id)}
					close(req.ch)
					continue
				}
			}

			err := client.SendContext(req.ctx, req.msg, conn, start)
			if err != nil {
				req.ch <- sharedClientResponse{nil, 0, err}
				close(req.ch)
			} else {
				waitingResponses[req.msg.Id] = waiter{req.ch, start}

				// If this message requires a larger receive buffer, ensure we allocate larger
				// buffers for this conn. It's theoretically possible that we're already blocking on
				// read with a receive buffer that's too small for responses for this query.
				// However, we only hit an issue if the large response in addition overtakes the
				// smaller response we're expecting. In this unlikely case, we'll error out for all
				// concurrent transactions of this endpoint - since this can only occur on UDP, the
				// client must be prepared to retry anyway.
				if edns := req.msg.IsEdns0(); edns != nil {
					if es := edns.UDPSize(); es > uint16(size.Load()) {
						size.Store(uint32(es))
					}
				}

				// Wake up the receiver that may be waiting to receive again
				triggerReceiver()
			}

		case resp, ok := <-responses:
			if !ok {
				// 'responses' is closed when the receive loop exits, so we quit as
				// nothing can be received any more
				return
			}
			if resp.err != nil {
				// ReadMsg failed, but we cannot match it to a request,
				// so complete all pending requests.
				for _, waiter := range waitingResponses {
					waiter.ch <- sharedClientResponse{nil, 0, resp.err}
					close(waiter.ch)
				}
				waitingResponses = make(map[uint16]waiter)
			} else if resp.msg != nil {
				if waiter, ok := waitingResponses[resp.msg.Id]; ok {
					delete(waitingResponses, resp.msg.Id)
					resp.rtt = time.Since(waiter.start)
					waiter.ch <- resp
					close(waiter.ch)
				}
			}
		}
	}
}

func (c *SharedClient) ExchangeSharedContext(ctx context.Context, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	c.Lock()
	if c.conn == nil {
		c.conn, err = c.DialContext(ctx, c.serverAddr)
		if err != nil {
			c.Unlock()
			return nil, 0, fmt.Errorf("failed to dial connection to %v: %w", c.serverAddr, err)
		}
		// Start handler for sending and receiving.
		c.wg.Add(1)
		go handler(&c.wg, c.Client, c.conn, c.requests, &c.udpSize)
	}
	c.Unlock()

	// This request keeps 'c.requests' open; sending a request may hang indefinitely if
	// the handler happens to quit at the same time. Use ctx.Done to avoid this.
	timeout := getTimeoutForRequest(c.Client)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	respCh := make(chan sharedClientResponse)
	select {
	case c.requests <- request{ctx: ctx, msg: m, ch: respCh}:
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}

	// Since c.requests is unbuffered, the handler is guaranteed to eventually close 'respCh'
	select {
	case resp := <-respCh:
		return resp.msg, resp.rtt, resp.err
	// This is just fail-safe mechanism in case there is another similar issue
	case <-time.After(time.Minute):
		return nil, 0, fmt.Errorf("timeout waiting for response")
	}
}

// close closes and waits for the close to finish.
// Must be called while holding client's lock.
func (c *SharedClient) close() {
	close(c.requests)
	c.wg.Wait()
	c.conn = nil
}

// Return the appropriate timeout for a specific request
func getTimeoutForRequest(c *dns.Client) time.Duration {
	wtimeout := c.WriteTimeout
	if wtimeout == 0 {
		// Some default timeout as seen in miekg/dns.
		wtimeout = time.Second * 2
	}

	var requestTimeout time.Duration
	if c.Timeout != 0 {
		requestTimeout = c.Timeout
	} else {
		requestTimeout = wtimeout
	}
	// net.Dialer.Timeout has priority if smaller than the timeouts computed so
	// far
	if c.Dialer != nil && c.Dialer.Timeout != 0 {
		if c.Dialer.Timeout < requestTimeout {
			requestTimeout = c.Dialer.Timeout
		}
	}
	return requestTimeout
}
