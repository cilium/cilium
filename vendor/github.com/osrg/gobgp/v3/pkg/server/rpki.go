// Copyright (C) 2015-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/rtr"
)

const (
	connectRetryInterval = 30
)

func before(a, b uint32) bool {
	return int32(a-b) < 0
}

type roaEventType uint8

const (
	roaConnected roaEventType = iota
	roaDisconnected
	roaRTR
	roaLifetimeout
)

type roaEvent struct {
	EventType roaEventType
	Src       string
	Data      []byte
	conn      *net.TCPConn
}

type roaManager struct {
	eventCh   chan *roaEvent
	clientMap map[string]*roaClient
	table     *table.ROATable
	logger    log.Logger
}

func newROAManager(table *table.ROATable, logger log.Logger) *roaManager {
	m := &roaManager{
		eventCh:   make(chan *roaEvent),
		clientMap: make(map[string]*roaClient),
		table:     table,
		logger:    logger,
	}
	return m
}

func (m *roaManager) enabled() bool {
	return len(m.clientMap) != 0
}

func (m *roaManager) AddServer(host string, lifetime int64) error {
	address, port, err := net.SplitHostPort(host)
	if err != nil {
		return err
	}
	if lifetime == 0 {
		lifetime = 3600
	}
	if _, ok := m.clientMap[host]; ok {
		return fmt.Errorf("ROA server exists %s", host)
	}
	m.clientMap[host] = newRoaClient(address, port, m.eventCh, lifetime)
	return nil
}

func (m *roaManager) DeleteServer(host string) error {
	client, ok := m.clientMap[host]
	if !ok {
		return fmt.Errorf("ROA server doesn't exists %s", host)
	}
	client.stop()
	m.table.DeleteAll(host)
	delete(m.clientMap, host)
	return nil
}

func (m *roaManager) Enable(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			client.enable(client.serialNumber)
			return nil
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) Disable(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			client.reset()
			m.table.DeleteAll(add)
			return nil
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) Reset(address string) error {
	return m.Disable(address)
}

func (m *roaManager) SoftReset(address string) error {
	for network, client := range m.clientMap {
		add, _, _ := net.SplitHostPort(network)
		if add == address {
			client.softReset()
			m.table.DeleteAll(network)
			return nil
		}
	}
	return fmt.Errorf("ROA server not found %s", address)
}

func (m *roaManager) ReceiveROA() chan *roaEvent {
	return m.eventCh
}

func (c *roaClient) lifetimeout() {
	c.eventCh <- &roaEvent{
		EventType: roaLifetimeout,
		Src:       c.host,
	}
}

func (m *roaManager) HandleROAEvent(ev *roaEvent) {
	client, y := m.clientMap[ev.Src]
	if !y {
		if ev.EventType == roaConnected {
			ev.conn.Close()
		}
		m.logger.Error("Can't find ROA server configuration",
			log.Fields{
				"Topic": "rpki",
				"Key":   ev.Src})
		return
	}
	switch ev.EventType {
	case roaDisconnected:
		m.logger.Info("ROA server is disconnected",
			log.Fields{
				"Topic": "rpki",
				"Key":   ev.Src})
		client.state.Downtime = time.Now().Unix()
		// clear state
		client.endOfData = false
		client.pendingROAs = make([]*table.ROA, 0)
		client.state.RpkiMessages = config.RpkiMessages{}
		client.conn = nil
		go client.tryConnect()
		client.timer = time.AfterFunc(time.Duration(client.lifetime)*time.Second, client.lifetimeout)
		client.oldSessionID = client.sessionID
	case roaConnected:
		m.logger.Info("ROA server is connected",
			log.Fields{
				"Topic": "rpki",
				"Key":   ev.Src})
		client.conn = ev.conn
		client.state.Uptime = time.Now().Unix()
		go client.established()
	case roaRTR:
		m.handleRTRMsg(client, &client.state, ev.Data)
	case roaLifetimeout:
		// a) already reconnected but hasn't received
		// EndOfData -> needs to delete stale ROAs
		// b) not reconnected -> needs to delete stale ROAs
		//
		// c) already reconnected and received EndOfData so
		// all stale ROAs were deleted -> timer was cancelled
		// so should not be here.
		if client.oldSessionID != client.sessionID {
			m.logger.Info("Reconnected, ignore timeout",
				log.Fields{
					"Topic": "rpki",
					"Key":   client.host})
		} else {
			m.logger.Info("Deleting all ROAs due to timeout",
				log.Fields{
					"Topic": "rpki",
					"Key":   client.host})
			m.table.DeleteAll(client.host)
		}
	}
}

func (m *roaManager) handleRTRMsg(client *roaClient, state *config.RpkiServerState, buf []byte) {
	received := &state.RpkiMessages.RpkiReceived

	m1, err := rtr.ParseRTR(buf)
	if err == nil {
		switch msg := m1.(type) {
		case *rtr.RTRSerialNotify:
			if before(client.serialNumber, msg.RTRCommon.SerialNumber) {
				client.enable(client.serialNumber)
			} else if client.serialNumber == msg.RTRCommon.SerialNumber {
				// nothing
			} else {
				// should not happen. try to get the whole ROAs.
				client.softReset()
			}
			received.SerialNotify++
		case *rtr.RTRSerialQuery:
		case *rtr.RTRResetQuery:
		case *rtr.RTRCacheResponse:
			received.CacheResponse++
			client.endOfData = false
		case *rtr.RTRIPPrefix:
			family := bgp.AFI_IP
			if msg.Type == rtr.RTR_IPV4_PREFIX {
				received.Ipv4Prefix++
			} else {
				family = bgp.AFI_IP6
				received.Ipv6Prefix++
			}
			roa := table.NewROA(family, msg.Prefix, msg.PrefixLen, msg.MaxLen, msg.AS, client.host)
			if (msg.Flags & 1) == 1 {
				if client.endOfData {
					m.table.Add(roa)
				} else {
					client.pendingROAs = append(client.pendingROAs, roa)
				}
			} else {
				m.table.Delete(roa)
			}
		case *rtr.RTREndOfData:
			received.EndOfData++
			if client.sessionID != msg.RTRCommon.SessionID {
				// remove all ROAs related with the
				// previous session
				m.table.DeleteAll(client.host)
			}
			client.sessionID = msg.RTRCommon.SessionID
			client.serialNumber = msg.RTRCommon.SerialNumber
			client.endOfData = true
			if client.timer != nil {
				client.timer.Stop()
				client.timer = nil
			}
			for _, roa := range client.pendingROAs {
				m.table.Add(roa)
			}
			client.pendingROAs = make([]*table.ROA, 0)
		case *rtr.RTRCacheReset:
			client.softReset()
			received.CacheReset++
		case *rtr.RTRErrorReport:
			received.Error++
		}
	} else {
		m.logger.Info("Failed to parse an RTR message",
			log.Fields{
				"Topic": "rpki",
				"Host":  client.host,
				"Error": err})
	}
}

func (m *roaManager) GetServers() []*config.RpkiServer {
	recordsV4, prefixesV4 := m.table.Info(bgp.RF_IPv4_UC)
	recordsV6, prefixesV6 := m.table.Info(bgp.RF_IPv6_UC)

	l := make([]*config.RpkiServer, 0, len(m.clientMap))
	for _, client := range m.clientMap {
		state := &client.state

		if client.conn == nil {
			state.Up = false
		} else {
			state.Up = true
		}
		f := func(m map[string]uint32, key string) uint32 {
			if r, ok := m[key]; ok {
				return r
			}
			return 0
		}
		state.RecordsV4 = f(recordsV4, client.host)
		state.RecordsV6 = f(recordsV6, client.host)
		state.PrefixesV4 = f(prefixesV4, client.host)
		state.PrefixesV6 = f(prefixesV6, client.host)
		state.SerialNumber = client.serialNumber

		addr, port, _ := net.SplitHostPort(client.host)
		l = append(l, &config.RpkiServer{
			Config: config.RpkiServerConfig{
				Address: addr,
				// Note: RpkiServerConfig.Port is uint32 type, but the TCP/UDP
				// port is 16-bit length.
				Port: func() uint32 { p, _ := strconv.ParseUint(port, 10, 16); return uint32(p) }(),
			},
			State: client.state,
		})
	}
	return l
}

type roaClient struct {
	host         string
	conn         *net.TCPConn
	state        config.RpkiServerState
	eventCh      chan *roaEvent
	sessionID    uint16
	oldSessionID uint16
	serialNumber uint32
	timer        *time.Timer
	lifetime     int64
	endOfData    bool
	pendingROAs  []*table.ROA
	cancelfnc    context.CancelFunc
	ctx          context.Context
}

func newRoaClient(address, port string, ch chan *roaEvent, lifetime int64) *roaClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &roaClient{
		host:        net.JoinHostPort(address, port),
		eventCh:     ch,
		lifetime:    lifetime,
		pendingROAs: make([]*table.ROA, 0),
		ctx:         ctx,
		cancelfnc:   cancel,
	}
	go c.tryConnect()
	return c
}

func (c *roaClient) enable(serial uint32) error {
	if c.conn != nil {
		r := rtr.NewRTRSerialQuery(c.sessionID, serial)
		data, _ := r.Serialize()
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.SerialQuery++
	}
	return nil
}

func (c *roaClient) softReset() error {
	if c.conn != nil {
		r := rtr.NewRTRResetQuery()
		data, _ := r.Serialize()
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.ResetQuery++
		c.endOfData = false
		c.pendingROAs = make([]*table.ROA, 0)
	}
	return nil
}

func (c *roaClient) reset() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *roaClient) stop() {
	c.cancelfnc()
	c.reset()
}

func (c *roaClient) tryConnect() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		if conn, err := net.Dial("tcp", c.host); err != nil {
			// better to use context with timeout
			time.Sleep(connectRetryInterval * time.Second)
		} else {
			c.eventCh <- &roaEvent{
				EventType: roaConnected,
				Src:       c.host,
				conn:      conn.(*net.TCPConn),
			}
			return
		}
	}
}

func (c *roaClient) established() (err error) {
	defer func() {
		c.conn.Close()
		c.eventCh <- &roaEvent{
			EventType: roaDisconnected,
			Src:       c.host,
		}
	}()

	if err := c.softReset(); err != nil {
		return err
	}

	for {
		header := make([]byte, rtr.RTR_MIN_LEN)
		if _, err = io.ReadFull(c.conn, header); err != nil {
			return err
		}
		totalLen := binary.BigEndian.Uint32(header[4:8])
		if totalLen < rtr.RTR_MIN_LEN {
			return fmt.Errorf("too short header length %v", totalLen)
		}

		body := make([]byte, totalLen-rtr.RTR_MIN_LEN)
		if _, err = io.ReadFull(c.conn, body); err != nil {
			return
		}

		c.eventCh <- &roaEvent{
			EventType: roaRTR,
			Src:       c.host,
			Data:      append(header, body...),
		}
	}
}
