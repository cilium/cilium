// Copyright 2016-2017 Authors of Cilium
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

package proxy

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

const (
	fieldConn     = "conn"
	fieldSize     = "size"
	fieldConnPair = "connPair"
)

type proxySocket struct {
	// listener is the TCP listener.
	listener net.Listener

	// locker protects closing the closing channel and accessing pairs.
	locker lock.Mutex

	closing chan struct{}

	// pairs is the set of active connection pairs.
	pairs []*connectionPair
}

func listenSocket(address string, mark int, transparent bool) (*proxySocket, error) {
	socket := &proxySocket{
		closing: make(chan struct{}),
	}

	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	family := syscall.AF_INET
	if addr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("unable to set SO_REUSEADDR socket option: %s", err)
	}

	if transparent {
		if family == syscall.AF_INET {
			err = syscall.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		} else {
			err = syscall.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		}
		if err != nil {
			return nil, fmt.Errorf("unable to set SO_TRANSPARENT socket option: %s", err)
		}
	}

	if mark != 0 {
		setFdMark(fd, mark)
	}

	sockAddr, err := ipToSockaddr(family, addr.IP, addr.Port, addr.Zone)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Bind(fd, sockAddr); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	f := os.NewFile(uintptr(fd), addr.String())
	defer f.Close()

	socket.listener, err = net.FileListener(f)
	if err != nil {
		return nil, err
	}

	return socket, nil
}

func setLinger(c net.Conn, linger time.Duration) error {
	if tcp, ok := c.(*net.TCPConn); ok {
		if err := tcp.SetLinger(int(linger.Seconds())); err != nil {
			return fmt.Errorf("unable to set SO_LINGER socket option: %s", err)
		}
	}

	return nil
}

// Accept calls Accept() on the listen socket of the proxy.
// If not nil, afterClose is called after the connection pair has been closed.
// If cascadeClose is true, the returned connectionPair will immediately be
// closed when this listen socket is closed.
func (s *proxySocket) Accept(cascadeClose bool) (*connectionPair, error) {
	c, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}

	// Set the SO_LINGER socket option so that a request connection is
	// guaranteed to be closed within the proxyConnectionCloseTimeout.
	// If the linger timeout expires, the connection is closed with a RST,
	// which is useful to signal to the client that the termination is
	// abnormal.
	if err = setLinger(c, proxyConnectionCloseTimeout); err != nil {
		c.Close()
		return nil, err
	}

	// Enable keepalive on all accepted connections to force data on the
	// TCP connection in regular intervals to ensure that the datapath
	// never expires state associated with this connection.
	if err = setKeepAlive(c); err != nil {
		c.Close()
		return nil, err
	}

	var afterClose func(*connectionPair)
	if cascadeClose {
		afterClose = s.connectionPairClosed
	}
	pair := newConnectionPair(afterClose)

	s.locker.Lock()
	if cascadeClose {
		s.pairs = append(s.pairs, pair)
	}
	pair.Rx.SetConnection(c)
	s.locker.Unlock()

	return pair, nil
}

func (s *proxySocket) connectionPairClosed(pair *connectionPair) {
	scopedLog := log.WithField(fieldConnPair, pair)
	scopedLog.Debug("Connection pair closed, removing from proxy socket cascading delete list")

	s.locker.Lock()
	defer s.locker.Unlock()
	for i, p := range s.pairs {
		if p == pair {
			scopedLog.Debug("Connection pair removed from proxy socket cascading delete list")
			// Delete the pair from the list.
			numPairs := len(s.pairs)
			s.pairs[i] = s.pairs[numPairs-1]
			s.pairs = s.pairs[:numPairs-1]
			return
		}
	}
}

// Close closes the proxy socket and stops accepting new connections.
func (s *proxySocket) Close() {
	s.locker.Lock()

	select {
	case <-s.closing:
		s.locker.Unlock()
		return
	default:
	}

	close(s.closing)
	s.listener.Close()

	pairs := s.pairs
	s.pairs = nil

	s.locker.Unlock()

	// Immediately close all connection pairs for which cascading close was
	// requested in Accept.
	for _, pair := range pairs {
		pair.Rx.Close()
	}
}

type socketQueue chan []byte

type proxyConnection struct {
	// isRequestDirection indicates the direction of the TCP connection:
	// ingress/request (true) or egress/response (false).
	isRequestDirection bool

	// conn is the underlying TCP connection.
	conn net.Conn

	// queue is the queue of messages to send.
	queue socketQueue

	// closeLocker is used to ensure the close channel may only be closed once.
	closeLocker lock.Mutex

	// close is the channel that is closed to indicate that the connection
	// must be closed. closeLocker must be held when attempting to close this
	// channel to prevent closing it multiple times.
	close chan struct{}

	// afterClose is a function that is called after the connection's queue is
	// closed.
	afterClose func()
}

func newProxyConnection(rx bool, afterClose func()) *proxyConnection {
	return &proxyConnection{
		isRequestDirection: rx,
		queue:              make(socketQueue, socketQueueSize),
		close:              make(chan struct{}),
		afterClose:         afterClose,
	}
}

// SetConnection associates an established connection to the proxy connection.
// It starts a goroutine to write Enqueue()ed messages into the connection.
func (c *proxyConnection) SetConnection(conn net.Conn) {
	if c.conn != nil {
		log.WithField(fieldConn, c).Panic("Established connection is already associated")
	}

	c.conn = conn
	go c.writeQueuedMessages()
}

func fmtAddress(a net.Addr) string {
	if a == nil {
		return "nil"
	}
	return a.String()
}

// Closed returns true if the connection is closed
func (c *proxyConnection) Closed() bool {
	return c == nil || c.conn == nil
}

func (c *proxyConnection) String() string {
	if c.isRequestDirection {
		if c.Closed() {
			return "rx:closed"
		}

		return fmt.Sprintf("rx:%s->%s",
			fmtAddress(c.conn.RemoteAddr()),
			fmtAddress(c.conn.LocalAddr()))
	}

	if c.Closed() {
		return "tx:closed"
	}

	return fmt.Sprintf("tx:%s->%s",
		fmtAddress(c.conn.LocalAddr()),
		fmtAddress(c.conn.RemoteAddr()))
}

func (c *proxyConnection) writeQueuedMessages() {
	scopedLog := log.WithField(fieldConn, c)
	defer c.Close()

	for {
		select {
		case <-c.close:
			scopedLog.Debug("Connection closed, message queue exiting")
			return

		case msg, more := <-c.queue:
			if !more {
				// This should never happen since the queue channel is never closed.
				return
			}

			// Write the entire message into the socket.
			_, err := c.conn.Write(msg)

			// Ignore any write errors in case the socket has been closed by this proxy.
			select {
			case <-c.close:
				scopedLog.Debug("Connection closed, message queue exiting")
				return
			default:
			}

			if err != nil {
				scopedLog.WithError(err).Warn("Error while writing to socket, closing socket")
				return
			}
		}
	}
}

func (c *proxyConnection) direction() string {
	if c.isRequestDirection {
		return "request"
	}
	return "response"
}

// Enqueue queues a message to be written into the connection.
func (c *proxyConnection) Enqueue(msg []byte) {
	scopedLog := log.WithFields(logrus.Fields{
		fieldConn: c,
		fieldSize: len(msg),
	})

	flowdebug.Log(scopedLog, fmt.Sprintf("Enqueueing %s message", c.direction()))

	select {
	case <-c.close:
		flowdebug.Log(scopedLog, fmt.Sprintf("%s connection is closed; dropping message", c.direction()))
	case c.queue <- msg:
		flowdebug.Log(scopedLog, fmt.Sprintf("Enqueued %s message", c.direction()))
	}
}

// Close closes this connection.
// The connection on the other side of the proxy is closed after it is queued
// for closing or after proxyConnectionCloseTimeout.
func (c *proxyConnection) Close() {
	scopedLog := log.WithField(fieldConn, c)

	c.closeLocker.Lock()
	select {
	case <-c.close:
		// Already closed. Nothing to do.
		c.closeLocker.Unlock()
		return
	default:
	}
	// Cause writeQueuedMessages to terminate.
	close(c.close)
	c.closeLocker.Unlock()

	// Actually close the TCP connection. This will unblock any eventually
	// blocking c.conn.Write call in writeQueuedMessages.
	if !c.Closed() {
		scopedLog.Debug("Closing socket")
		c.conn.Close()
	}

	// Call connectionPair.close() concurrently so that this call doesn't block
	// while waiting for the other connection in the pair to close.
	go c.afterClose()
}

type connectionPair struct {
	Rx, Tx         *proxyConnection
	afterCloseOnce sync.Once
	afterClose     func()
}

func newConnectionPair(afterClose func(*connectionPair)) *connectionPair {
	pair := &connectionPair{}
	pair.Rx = newProxyConnection(true, pair.close)
	pair.Tx = newProxyConnection(false, pair.close)
	if afterClose != nil {
		pair.afterClose = func() { afterClose(pair) }
	}
	return pair
}

func (p *connectionPair) String() string {
	return p.Rx.String() + "<->" + p.Tx.String()
}

func (p *connectionPair) close() {
	scopedLog := log.WithField(fieldConnPair, p)

	// Wait for both Rx and Tx to be closed or for timeout.
	timeout := time.NewTimer(proxyConnectionCloseTimeout)
	var bothClosed bool
	select {
	case <-p.Rx.close:
		scopedLog.Debug("Rx is already closed, waiting for Tx to close")
		// Rx is closed. Wait for Tx to close or timeout.
		select {
		case <-p.Tx.close:
			bothClosed = true
		case <-timeout.C:
			scopedLog.Debug("Timeout while waiting for Tx to close; closing Tx")
			p.Tx.Close()
		}
	case <-p.Tx.close:
		// Tx is closed. Wait for Rx to close or timeout.
		scopedLog.Debug("Tx is already closed, waiting for Rx to close")
		select {
		case <-p.Rx.close:
			bothClosed = true
		case <-timeout.C:
			scopedLog.Debug("Timeout while waiting for Rx to close; closing Rx")
			p.Rx.Close()
		}
	default:
		// This case should never be selected, since connectionPair.close() is
		// called only from proxyConnection.Close() after the close channel is
		// closed, so at least one of the cases above can always be selected.
	}
	timeout.Stop()

	if bothClosed {
		scopedLog.Debug("Both Rx and Tx are closed")
		if p.afterClose != nil {
			p.afterCloseOnce.Do(p.afterClose)
		}
	}
}

func lookupSrcID(remoteAddr, localAddr string, ingress bool) (uint32, error) {
	val, err := ctmap.Lookup(remoteAddr, localAddr, u8proto.TCP, ingress)
	if err != nil {
		flowdebug.Log(log.WithField(logfields.Object, logfields.Repr(val)), "Did not find proxy entry!")
		return 0, err
	}

	flowdebug.Log(log.WithField(logfields.Object, logfields.Repr(val)), "Found proxy entry")

	return val.SourceSecurityID, nil
}

func setFdMark(fd, mark int) {
	scopedLog := log.WithFields(logrus.Fields{
		fieldFd:     fd,
		fieldMarker: mark,
	})
	flowdebug.Log(scopedLog, "Setting packet marker of socket")

	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	if err != nil {

		scopedLog.WithError(err).Warn("Unable to set SO_MARK")
	}
}

func setSocketMark(c net.Conn, mark int) {
	if tc, ok := c.(*net.TCPConn); ok {
		if f, err := tc.File(); err == nil {
			defer f.Close()
			setFdMark(int(f.Fd()), mark)
		}
	}
}
