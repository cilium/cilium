// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// SharedClients holds a set of SharedClient instances.
type SharedClients struct {
	// SharedClient's lock must not be taken while this lock is held!
	lock sync.Mutex
	// clients are created and destroyed on demand, hence 'Mutex' needs to be taken.
	clients map[string]*SharedClient
}

func NewSharedClients() *SharedClients {
	return &SharedClients{
		clients: make(map[string]*SharedClient),
	}
}

func (s *SharedClients) Exchange(key string, conf *Client, m *Msg, serverAddrStr string) (r *Msg, rtt time.Duration, closer func(), err error) {
	return s.ExchangeContext(context.Background(), key, conf, m, serverAddrStr)
}

func (s *SharedClients) ExchangeContext(ctx context.Context, key string, conf *Client, m *Msg, serverAddrStr string) (r *Msg, rtt time.Duration, closer func(), err error) {
	client, closer := s.GetSharedClient(key, conf, serverAddrStr)
	r, rtt, err = client.ExchangeSharedContext(ctx, m)
	return r, rtt, closer, err
}

// GetSharedClient gets or creates an instance of SharedClient keyed with 'key'.  if 'key' is an
// empty sting, a new client is always created and it is not actually shared.  The returned 'closer'
// must be called once the client is no longer needed. Conversely, the returned 'client' must not be
// used after the closer is called.
func (s *SharedClients) GetSharedClient(key string, conf *Client, serverAddrStr string) (client *SharedClient, closer func()) {
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
	msg *Msg
	ch  chan sharedClientResponse
}

type sharedClientResponse struct {
	msg *Msg
	rtt time.Duration
	err error
}

// A SharedClient keeps state for concurrent transactions on the same upstream client/connection.
type SharedClient struct {
	serverAddr string

	*Client

	// requests is closed when the client needs to exit
	requests chan request
	// wg is waited on for the client finish exiting
	wg sync.WaitGroup

	sync.Mutex // protects the fields below
	refcount   int
	conn       *Conn
}

func newSharedClient(conf *Client, serverAddr string) *SharedClient {
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
func (c *SharedClient) ExchangeShared(m *Msg) (r *Msg, rtt time.Duration, err error) {
	return c.ExchangeSharedContext(context.Background(), m)
}

// handler is started when the connection is dialed
func handler(wg *sync.WaitGroup, client *Client, conn *Conn, requests chan request) {
	defer wg.Done()

	responses := make(chan sharedClientResponse)

	// Receive loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(responses)
		for {
			r, err := conn.ReadMsg()
			if err != nil {
				// handler is not reading on the channel after closing
				if errors.Is(err, net.ErrClosed) {
					return
				}
				responses <- sharedClientResponse{nil, 0, err}
			} else {
				responses <- sharedClientResponse{r, 0, nil}
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
				return
			}
			start := time.Now()
			err := client.SendContext(req.ctx, req.msg, conn, start)
			if err != nil {
				req.ch <- sharedClientResponse{nil, 0, err}
				close(req.ch)
			} else {
				waitingResponses[req.msg.Id] = waiter{req.ch, start}
			}

		case resp, ok := <-responses:
			if !ok {
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

func (c *SharedClient) ExchangeSharedContext(ctx context.Context, m *Msg) (r *Msg, rtt time.Duration, err error) {
	c.Lock()
	if c.conn == nil {
		c.conn, err = c.DialContext(ctx, c.serverAddr)
		if err != nil {
			c.Unlock()
			return nil, 0, fmt.Errorf("failed to dial connection to %v: %w", c.serverAddr, err)
		}
		// Start handler for sending and receiving.
		c.wg.Add(1)
		go handler(&c.wg, c.Client, c.conn, c.requests)
	}
	c.Unlock()

	respCh := make(chan sharedClientResponse)
	c.requests <- request{
		ctx: ctx,
		msg: m,
		ch:  respCh,
	}
	resp := <-respCh
	return resp.msg, resp.rtt, resp.err
}

// close closes and waits for the close to finish.
// Must be called while holding client's lock.
func (c *SharedClient) close() {
	close(c.requests)
	c.wg.Wait()
	c.conn = nil
}
