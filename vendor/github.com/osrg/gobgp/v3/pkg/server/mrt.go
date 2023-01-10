// Copyright (C) 2016-2021 Nippon Telegraph and Telephone Corporation.
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
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/mrt"
)

const (
	minRotationInterval = 60
	minDumpInterval     = 60
)

type mrtWriter struct {
	dead             chan struct{}
	s                *BgpServer
	c                *config.MrtConfig
	file             *os.File
	rotationInterval uint64
	dumpInterval     uint64
}

func (m *mrtWriter) Stop() {
	close(m.dead)
}

func (m *mrtWriter) loop() error {
	ops := []watchOption{}
	switch m.c.DumpType {
	case config.MRT_TYPE_UPDATES:
		ops = append(ops, watchUpdate(false, ""))
	case config.MRT_TYPE_TABLE:
		if len(m.c.TableName) > 0 {
			ops = append(ops, watchTableName(m.c.TableName))
		}
	}
	w := m.s.watch(ops...)
	rotator := func() *time.Ticker {
		if m.rotationInterval == 0 {
			return &time.Ticker{}
		}
		return time.NewTicker(time.Second * time.Duration(m.rotationInterval))
	}()
	dump := func() *time.Ticker {
		if m.dumpInterval == 0 {
			return &time.Ticker{}
		}
		return time.NewTicker(time.Second * time.Duration(m.dumpInterval))
	}()

	defer func() {
		if m.file != nil {
			m.file.Close()
		}
		if m.rotationInterval != 0 {
			rotator.Stop()
		}
		if m.dumpInterval != 0 {
			dump.Stop()
		}
		w.Stop()
	}()

	for {
		serialize := func(ev watchEvent) []*mrt.MRTMessage {
			msg := make([]*mrt.MRTMessage, 0, 1)
			switch e := ev.(type) {
			case *watchEventUpdate:
				if e.Init {
					return nil
				}
				mp := mrt.NewBGP4MPMessage(e.PeerAS, e.LocalAS, 0, e.PeerAddress.String(), e.LocalAddress.String(), e.FourBytesAs, nil)
				mp.BGPMessagePayload = e.Payload
				isAddPath := e.Neighbor.IsAddPathReceiveEnabled(e.PathList[0].GetRouteFamily())
				subtype := mrt.MESSAGE
				switch {
				case isAddPath && e.FourBytesAs:
					subtype = mrt.MESSAGE_AS4_ADDPATH
				case isAddPath:
					subtype = mrt.MESSAGE_ADDPATH
				case e.FourBytesAs:
					subtype = mrt.MESSAGE_AS4
				}
				if bm, err := mrt.NewMRTMessage(uint32(e.Timestamp.Unix()), mrt.BGP4MP, subtype, mp); err != nil {
					m.s.logger.Warn("Failed to create MRT BGP4MP message",
						log.Fields{
							"Topic":   "mrt",
							"Data":    e,
							"Error":   err,
							"Subtype": subtype})
				} else {
					msg = append(msg, bm)
				}
			case *watchEventTable:
				t := uint32(time.Now().Unix())

				peers := make([]*mrt.Peer, 1, len(e.Neighbor)+1)
				// Adding dummy Peer record for locally generated routes
				peers[0] = mrt.NewPeer("0.0.0.0", "0.0.0.0", 0, true)
				neighborMap := make(map[string]*config.Neighbor)
				for _, pconf := range e.Neighbor {
					peers = append(peers, mrt.NewPeer(pconf.State.RemoteRouterId, pconf.State.NeighborAddress, pconf.Config.PeerAs, true))
					neighborMap[pconf.State.NeighborAddress] = pconf
				}

				if bm, err := mrt.NewMRTMessage(t, mrt.TABLE_DUMPv2, mrt.PEER_INDEX_TABLE, mrt.NewPeerIndexTable(e.RouterID, "", peers)); err != nil {
					m.s.logger.Warn("Failed to create MRT TABLE_DUMPv2 message",
						log.Fields{
							"Topic":   "mrt",
							"Data":    e,
							"Error":   err,
							"Subtype": mrt.PEER_INDEX_TABLE})
					break
				} else {
					msg = append(msg, bm)
				}

				idx := func(p *table.Path) uint16 {
					for i, peer := range peers {
						if peer.IpAddress.String() == p.GetSource().Address.String() {
							return uint16(i)
						}
					}
					return uint16(len(peers))
				}

				subtype := func(p *table.Path, isAddPath bool) mrt.MRTSubTypeTableDumpv2 {
					t := mrt.RIB_GENERIC
					switch p.GetRouteFamily() {
					case bgp.RF_IPv4_UC:
						t = mrt.RIB_IPV4_UNICAST
					case bgp.RF_IPv4_MC:
						t = mrt.RIB_IPV4_MULTICAST
					case bgp.RF_IPv6_UC:
						t = mrt.RIB_IPV6_UNICAST
					case bgp.RF_IPv6_MC:
						t = mrt.RIB_IPV6_MULTICAST
					}
					if isAddPath {
						// Shift non-additional-path version to *_ADDPATH
						t += 6
					}
					return t
				}

				seq := uint32(0)
				appendTableDumpMsg := func(path *table.Path, entries []*mrt.RibEntry, isAddPath bool) {
					st := subtype(path, isAddPath)
					if bm, err := mrt.NewMRTMessage(t, mrt.TABLE_DUMPv2, st, mrt.NewRib(seq, path.GetNlri(), entries)); err != nil {
						m.s.logger.Warn("Failed to create MRT TABLE_DUMPv2 message",
							log.Fields{
								"Topic":   "mrt",
								"Data":    e,
								"Error":   err,
								"Subtype": st})
					} else {
						msg = append(msg, bm)
						seq++
					}
				}
				for _, pathList := range e.PathList {
					entries := make([]*mrt.RibEntry, 0, len(pathList))
					entriesAddPath := make([]*mrt.RibEntry, 0, len(pathList))
					for _, path := range pathList {
						isAddPath := false
						if path.IsLocal() {
							isAddPath = true
						} else if neighbor, ok := neighborMap[path.GetSource().Address.String()]; ok {
							isAddPath = neighbor.IsAddPathReceiveEnabled(path.GetRouteFamily())
						}
						if !isAddPath {
							entries = append(entries, mrt.NewRibEntry(idx(path), uint32(path.GetTimestamp().Unix()), 0, path.GetPathAttrs(), false))
						} else {
							entriesAddPath = append(entriesAddPath, mrt.NewRibEntry(idx(path), uint32(path.GetTimestamp().Unix()), path.GetNlri().PathIdentifier(), path.GetPathAttrs(), true))
						}
					}
					if len(entries) > 0 {
						appendTableDumpMsg(pathList[0], entries, false)
					}
					if len(entriesAddPath) > 0 {
						appendTableDumpMsg(pathList[0], entriesAddPath, true)
					}
				}
			}
			return msg
		}

		drain := func(ev watchEvent) {
			events := make([]watchEvent, 0, 1+len(w.Event()))
			if ev != nil {
				events = append(events, ev)
			}

			for len(w.Event()) > 0 {
				events = append(events, <-w.Event())
			}

			w := func(buf []byte) {
				if _, err := m.file.Write(buf); err == nil {
					m.file.Sync()
				} else {
					m.s.logger.Warn("Can't write to destination MRT file",
						log.Fields{
							"Topic": "mrt",
							"Error": err})
				}
			}

			var b bytes.Buffer
			for _, e := range events {
				for _, msg := range serialize(e) {
					if buf, err := msg.Serialize(); err != nil {
						m.s.logger.Warn("Failed to serialize event",
							log.Fields{
								"Topic": "mrt",
								"Data":  e,
								"Error": err})
					} else {
						b.Write(buf)
						if b.Len() > 1*1000*1000 {
							w(b.Bytes())
							b.Reset()
						}
					}
				}
			}
			if b.Len() > 0 {
				w(b.Bytes())
			}
		}
		rotate := func() {
			m.file.Close()
			file, err := mrtFileOpen(m.s.logger, m.c.FileName, m.rotationInterval)
			if err == nil {
				m.file = file
			} else {
				m.s.logger.Warn("can't rotate MRT file",
					log.Fields{
						"Topic": "mrt",
						"Error": err})
			}
		}

		select {
		case <-m.dead:
			drain(nil)
			return nil
		case e := <-w.Event():
			drain(e)
			if m.c.DumpType == config.MRT_TYPE_TABLE && m.rotationInterval != 0 {
				rotate()
			}
		case <-rotator.C:
			if m.c.DumpType == config.MRT_TYPE_UPDATES {
				rotate()
			} else {
				w.Generate(watchEventTypeTable)
			}
		case <-dump.C:
			w.Generate(watchEventTypeTable)
		}
	}
}

func mrtFileOpen(logger log.Logger, filename string, rInterval uint64) (*os.File, error) {
	realname := filename
	if rInterval != 0 {
		realname = time.Now().Format(filename)
	}
	logger.Debug("Setting new MRT destination file",
		log.Fields{
			"Topic":            "mrt",
			"Filename":         realname,
			"RotationInterval": rInterval})

	i := len(realname)
	for i > 0 && os.IsPathSeparator(realname[i-1]) {
		// skip trailing path separators
		i--
	}
	j := i

	for j > 0 && !os.IsPathSeparator(realname[j-1]) {
		j--
	}

	if j > 0 {
		if err := os.MkdirAll(realname[0:j-1], 0755); err != nil {
			logger.Warn("can't create MRT destination directory",
				log.Fields{
					"Topic": "mrt",
					"Error": err})
			return nil, err
		}
	}

	file, err := os.OpenFile(realname, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		logger.Warn("can't create MRT destination file",
			log.Fields{
				"Topic": "mrt",
				"Error": err})
	}
	return file, err
}

func newMrtWriter(s *BgpServer, c *config.MrtConfig, rInterval, dInterval uint64) (*mrtWriter, error) {
	file, err := mrtFileOpen(s.logger, c.FileName, rInterval)
	if err != nil {
		return nil, err
	}
	m := mrtWriter{
		s:                s,
		c:                c,
		file:             file,
		rotationInterval: rInterval,
		dumpInterval:     dInterval,
	}
	go m.loop()
	return &m, nil
}

type mrtManager struct {
	bgpServer *BgpServer
	writer    map[string]*mrtWriter
}

func (m *mrtManager) enable(c *config.MrtConfig) error {
	if _, ok := m.writer[c.FileName]; ok {
		return fmt.Errorf("%s already exists", c.FileName)
	}

	rInterval := c.RotationInterval
	dInterval := c.DumpInterval

	setRotationMin := func() {
		if rInterval < minRotationInterval {
			m.bgpServer.logger.Info("use minimum mrt rotation interval",
				log.Fields{
					"Topic":    "mrt",
					"Interval": minRotationInterval})
			rInterval = minRotationInterval
		}
	}

	if c.DumpType == config.MRT_TYPE_TABLE {
		if rInterval == 0 {
			if dInterval < minDumpInterval {
				m.bgpServer.logger.Info("use minimum mrt dump interval",
					log.Fields{
						"Topic":    "mrt",
						"Interval": minDumpInterval})
				dInterval = minDumpInterval
			}
		} else if dInterval == 0 {
			setRotationMin()
		} else {
			return fmt.Errorf("can't specify both intervals in the table dump type")
		}
	} else if c.DumpType == config.MRT_TYPE_UPDATES {
		// ignore the dump interval
		dInterval = 0
		if len(c.TableName) > 0 {
			return fmt.Errorf("can't specify the table name with the update dump type")
		}
		setRotationMin()
	}

	w, err := newMrtWriter(m.bgpServer, c, rInterval, dInterval)
	if err == nil {
		m.writer[c.FileName] = w
	}
	return err
}

func (m *mrtManager) disable(c *config.MrtConfig) error {
	w, ok := m.writer[c.FileName]
	if !ok {
		return fmt.Errorf("%s doesn't exists", c.FileName)
	}
	w.Stop()
	delete(m.writer, c.FileName)
	return nil
}

func newMrtManager(s *BgpServer) *mrtManager {
	return &mrtManager{
		bgpServer: s,
		writer:    make(map[string]*mrtWriter),
	}
}
