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
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/logfields"

	log "github.com/sirupsen/logrus"
)

const (
	fieldConn = "conn"
	fieldSize = "size"
)

type proxySocket struct {
	listener net.Listener
	closing  chan struct{}
}

func listenSocket(address string, mark int) (*proxySocket, error) {
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

// Accept calls Accept() on the listen socket of the proxy
func (s *proxySocket) Accept() (*connectionPair, error) {
	c, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}

	pair := newConnectionPair()
	pair.rx.SetConnection(c)

	return pair, nil
}

// Close closes the proxy socket and stops accepting new connections
func (s *proxySocket) Close() {
	close(s.closing)
	s.listener.Close()
}

type socketQueue chan []byte

type proxyConnection struct {
	// isRequestDirection whether the connection represents
	isRequestDirection bool

	// queueStopCount is > 0 if the queue has been stopped, it may only be
	// read with queueStopped()
	queueStopCount int32

	conn  net.Conn
	queue socketQueue

	stopQueue chan struct{}

	queueClose func()
}

func newProxyConnection(rx bool, queueClose func()) *proxyConnection {
	return &proxyConnection{
		isRequestDirection: rx,
		queue:              make(socketQueue, socketQueueSize),
		stopQueue:          make(chan struct{}),
		queueClose:         queueClose,
	}
}

// SetConnection associates an established connection to the proxy connection.
// It will also start a go routine to sync Enqueue()ed messages to the
// connection
func (c *proxyConnection) SetConnection(conn net.Conn) {
	if c.conn != nil {
		log.WithFields(log.Fields{
			fieldConn: c,
		}).Panic("Established connection is already associated")
	}

	c.conn = conn
	c.startWriter()
}

func (c *proxyConnection) queueStopped() bool {
	return atomic.LoadInt32(&c.queueStopCount) > 0
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

func (c *proxyConnection) startWriter() {
	go c.socketWriter()
}

func (c *proxyConnection) socketWriter() {
	defer c.queueClose()

	for {
		select {
		case <-c.stopQueue:
			atomic.AddInt32(&c.queueStopCount, 1)
			return

		case msg, more := <-c.queue:
			if more {
				// write entire message to socket
				_, err := c.conn.Write(msg)
				if err != nil {
					log.WithError(err).WithField(fieldConn, c).Warn("Error while writing to socket, closing socket")
					return
				}
			} else {
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

// Enqueue queues a message to be written to the socket
func (c *proxyConnection) Enqueue(msg []byte) {
	scopedLog := log.WithFields(log.Fields{
		fieldConn: c,
		fieldSize: len(msg),
	})

	if c.queueStopped() {
		scopedLog.Debug("Dropping message, queue is stopped")
		return
	}

	scopedLog.Debugf("Enqueueing %s message", c.direction())

	c.queue <- msg
}

// Close schedules closing of one side of the proxied connection. It will drain
// the queue and then mark the connection to be closed. The connections are closed
// simultaneously after both connections have been queued for closing or after
// proxyConnectionCloseTimeout
func (c *proxyConnection) Close() {
	// stop writer queue and wait for the queue to be drained
	close(c.stopQueue)
}

func (c *proxyConnection) realClose() {
	log.WithField(fieldConn, c).Debug("Closing socket")

	close(c.queue)

	if !c.Closed() {
		c.conn.Close()
	}
}

type connectionPair struct {
	// closingCount is used to count the close calls of both connection and
	// only close both connections when both connections have triggered
	// closure.
	closingCount int32

	rx, tx *proxyConnection
}

func newConnectionPair() *connectionPair {
	pair := &connectionPair{}
	pair.rx = newProxyConnection(true, pair.queueClose)
	pair.tx = newProxyConnection(false, pair.queueClose)

	return pair
}

func (p *connectionPair) String() string {
	return p.rx.String() + "<->" + p.tx.String()
}

func (p *connectionPair) closeBoth() {
	p.rx.realClose()
	p.tx.realClose()
}

func (p *connectionPair) queueClose() {
	// If this is the first side to close the connection, keep it open
	// until other side is closed or until timeout occurs
	if v := atomic.AddInt32(&p.closingCount, 1); v == 1 {
		time.AfterFunc(time.Minute, func() {
			// test if the other connection is still alive before closing conn
			if atomic.AddInt32(&p.closingCount, 1) == 2 {
				p.closeBoth()
			}
		})
	} else if v == 2 {
		p.closeBoth()
	}
}

func (p *connectionPair) CloseRx() {
	p.rx.conn.Close()
}

func lookupNewDest(remoteAddr string, dport uint16) (uint32, string, error) {
	ip, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid remote address: %s", err)
	}

	pIP := net.ParseIP(ip)
	if pIP == nil {
		return 0, "", fmt.Errorf("unable to parse IP %s", ip)
	}

	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf("unable to parse port string: %s", err)
	}

	if pIP.To4() != nil {
		key := &Proxy4Key{
			SPort:   uint16(sport),
			DPort:   dport,
			Nexthdr: 6,
		}

		copy(key.SAddr[:], pIP.To4())

		val, err := LookupEgress4(key)
		if err != nil {
			return 0, "", fmt.Errorf("Unable to find IPv4 proxy entry for %s: %s", key, err)
		}

		log.WithField(logfields.Object, logfields.Repr(val)).Debug("Found IPv4 proxy entry")
		return val.SourceIdentity, val.HostPort(), nil
	}

	key := &Proxy6Key{
		SPort:   uint16(sport),
		DPort:   dport,
		Nexthdr: 6,
	}

	copy(key.SAddr[:], pIP.To16())

	val, err := LookupEgress6(key)
	if err != nil {
		return 0, "", fmt.Errorf("Unable to find IPv6 proxy entry for %s: %s", key, err)
	}

	log.WithField(logfields.Object, logfields.Repr(val)).Debug("Found IPv6 proxy entry")
	return val.SourceIdentity, val.HostPort(), nil
}

type proxyIdentity int

const identityKey proxyIdentity = 0

func newIdentityContext(ctx context.Context, id int) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func identityFromContext(ctx context.Context) (int, bool) {
	val, ok := ctx.Value(identityKey).(int)
	return val, ok
}

func setFdMark(fd, mark int) {
	scopedLog := log.WithFields(log.Fields{
		fieldFd:     fd,
		fieldMarker: mark,
	})
	scopedLog.Debug("Setting packet marker of socket")

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
