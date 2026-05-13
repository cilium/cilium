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
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/mrt"
)

const (
	minRotationInterval = 60
	minDumpInterval     = 60
)

type mrtWriter struct {
	cancel           context.CancelFunc
	s                *BgpServer
	c                *oc.MrtConfig
	file             *os.File
	rotationInterval uint64
	dumpInterval     uint64
}

func (m *mrtWriter) Stop() {
	m.cancel()
}

type dumpPeer struct {
	index uint16

	id   netip.Addr
	addr netip.Addr
	as   uint32
}

func (m *mrtWriter) dumpTable() []*mrt.MRTMessage {
	m.s.shared.mu.Lock()
	defer m.s.shared.mu.Unlock()

	msgs := make([]*mrt.MRTMessage, 0)

	t := time.Now()

	peermap := make(map[netip.Addr]dumpPeer)

	idx := func(p *table.Path) uint16 {
		if p, ok := peermap[p.GetSource().Address]; ok {
			return p.index
		}
		newIdx := uint16(len(peermap))
		if p.GetSource().Address == netip.IPv4Unspecified() {
			// Adding dummy Peer record for locally generated routes
			peermap[netip.IPv4Unspecified()] = dumpPeer{
				index: newIdx,
				addr:  netip.IPv4Unspecified(),
				id:    netip.IPv4Unspecified(),
				as:    0,
			}
		} else {
			peermap[p.GetSource().Address] = dumpPeer{
				index: newIdx,
				addr:  p.GetSource().Address,
				id:    p.GetSource().ID,
			}
		}
		return newIdx
	}

	subtype := func(p *table.Path, isAddPath bool) mrt.MRTSubTypeTableDumpv2 {
		t := mrt.RIB_GENERIC
		switch p.GetFamily() {
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
		if bm, err := mrt.NewMRTMessage(t, mrt.TABLE_DUMPv2, st, mrt.NewRib(seq, path.GetFamily(), path.GetNlri(), entries)); err != nil {
			m.s.logger.Warn("Failed to create MRT TABLE_DUMPv2 message",
				slog.String("Topic", "mrt"),
				slog.String("Error", err.Error()),
				slog.String("Data", path.String()))
		} else {
			msgs = append(msgs, bm)
			seq++
		}
	}

	rib := m.s.globalRib
	as := uint32(0)
	id := table.GLOBAL_RIB_NAME
	if m.c.TableName.IsValid() {
		peer, ok := m.s.neighborMap[m.c.TableName]
		if !ok {
			return []*mrt.MRTMessage{}
		}
		if !peer.isRouteServerClient() {
			return []*mrt.MRTMessage{}
		}
		id = peer.ID()
		as = peer.AS()
		rib = m.s.rsRib
	}

	for family, t := range rib.GetAllTablesMap() {
		for _, dst := range t.GetDestinations() {
			if paths := dst.GetKnownPathList(id, as); len(paths) > 0 {
				entries := make([]*mrt.RibEntry, 0)
				entriesAddPath := make([]*mrt.RibEntry, 0)
				for _, path := range paths {
					isAddPath := false
					if path.IsLocal() {
						isAddPath = true
					} else if neighbor, ok := m.s.neighborMap[path.GetSource().Address]; ok {
						isAddPath = neighbor.isAddPathReceiveEnabled(family)
					}
					if !isAddPath {
						entries = append(entries, mrt.NewRibEntry(idx(path), uint32(path.GetTimestamp().Unix()), 0, path.GetPathAttrs(), false))
					} else {
						entriesAddPath = append(entriesAddPath, mrt.NewRibEntry(idx(path), uint32(path.GetTimestamp().Unix()), path.RemoteID(), path.GetPathAttrs(), true))
					}
				}
				if len(entries) > 0 {
					appendTableDumpMsg(paths[0], entries, false)
				}
				if len(entriesAddPath) > 0 {
					appendTableDumpMsg(paths[0], entriesAddPath, true)
				}
			}
		}
	}

	bm, err := func() (*mrt.MRTMessage, error) {
		dpeers := make([]dumpPeer, 0)
		for _, p := range peermap {
			dpeers = append(dpeers, p)
		}
		sort.Slice(dpeers, func(i, j int) bool {
			return dpeers[i].index < dpeers[j].index
		})

		peers := make([]*mrt.Peer, 0, len(dpeers))
		for _, p := range dpeers {
			peers = append(peers, mrt.NewPeer(p.id, p.addr, p.as, true))
		}

		return mrt.NewMRTMessage(t, mrt.TABLE_DUMPv2, mrt.PEER_INDEX_TABLE, mrt.NewPeerIndexTable(m.s.bgpConfig.Global.Config.RouterId, "", peers))
	}()
	if err != nil {
		return []*mrt.MRTMessage{}
	}

	return append([]*mrt.MRTMessage{bm}, msgs...)
}

func (m *mrtWriter) loop(ctx context.Context) error {
	ops := []WatchOption{}
	switch m.c.DumpType {
	case oc.MRT_TYPE_UPDATES:
		ops = append(ops, WatchUpdate(false, "", ""))
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

	eventToMrtMsg := func(ev watchEvent) []*mrt.MRTMessage {
		msg := make([]*mrt.MRTMessage, 0, 1)
		switch e := ev.(type) {
		case *watchEventUpdate:
			if e.Init {
				return nil
			}
			// MRT encodes IP addresses and does not carry zone information.
			mp, _ := mrt.NewBGP4MPMessage(e.PeerAS, e.LocalAS, 0, e.PeerAddress.WithZone(""), e.LocalAddress.WithZone(""), e.FourBytesAs, nil)
			mp.BGPMessagePayload = e.Payload
			isAddPath := e.Neighbor.IsAddPathReceiveEnabled(e.PathList[0].GetFamily())
			subtype := mrt.MESSAGE
			switch {
			case isAddPath && e.FourBytesAs:
				subtype = mrt.MESSAGE_AS4_ADDPATH
			case isAddPath:
				subtype = mrt.MESSAGE_ADDPATH
			case e.FourBytesAs:
				subtype = mrt.MESSAGE_AS4
			}
			if bm, err := mrt.NewMRTMessage(e.Timestamp, mrt.BGP4MP, subtype, mp); err != nil {
				m.s.logger.Warn("Failed to create MRT BGP4MP message",
					slog.String("Topic", "mrt"),
					slog.Any("Data", e),
					slog.String("Error", err.Error()),
					slog.Any("Subtype", subtype),
				)
			} else {
				msg = append(msg, bm)
			}
		}
		return msg
	}

	writeToFile := func(msgs []*mrt.MRTMessage) {
		w := func(buf []byte) {
			if _, err := m.file.Write(buf); err == nil {
				m.file.Sync()
			} else {
				m.s.logger.Warn("Can't write to destination MRT file",
					slog.String("Topic", "mrt"),
					slog.String("Error", err.Error()),
				)
			}
		}

		var b bytes.Buffer
		for _, msg := range msgs {
			if buf, err := msg.Serialize(); err != nil {
				m.s.logger.Warn("Failed to serialize event",
					slog.String("Topic", "mrt"),
					slog.String("Error", err.Error()))
			} else {
				b.Write(buf)
				if b.Len() > 1*1000*1000 {
					w(b.Bytes())
					b.Reset()
				}
			}
		}
		if b.Len() > 0 {
			w(b.Bytes())
		}
	}

	rotateFile := func() {
		m.file.Close()
		file, err := mrtFileOpen(m.s.logger, m.c.FileName, m.rotationInterval)
		if err == nil {
			m.file = file
		} else {
			m.s.logger.Warn("can't rotate MRT file",
				slog.String("Topic", "mrt"),
				slog.String("Error", err.Error()))
		}
	}

	for {
		msgs := make([]*mrt.MRTMessage, 0)
		select {
		case <-ctx.Done():
			// nothing
		case e := <-w.Event():
			msgs = append(msgs, eventToMrtMsg(e)...)
			if m.c.DumpType == oc.MRT_TYPE_TABLE && m.rotationInterval != 0 {
				rotateFile()
			}
		case <-rotator.C:
			if m.c.DumpType == oc.MRT_TYPE_UPDATES {
				rotateFile()
			} else {
				msgs = append(msgs, m.dumpTable()...)
			}
		case <-dump.C:
			msgs = append(msgs, m.dumpTable()...)
		}

		for len(w.Event()) > 0 {
			msgs = append(msgs, eventToMrtMsg(<-w.Event())...)
		}
		writeToFile(msgs)

		if ctx.Err() != nil {
			return nil
		}
	}
}

func mrtFileOpen(logger *slog.Logger, filename string, rInterval uint64) (*os.File, error) {
	realname := filename
	if rInterval != 0 {
		realname = time.Now().Format(filename)
	}
	logger.Debug("Setting new MRT destination file",
		slog.String("Topic", "mrt"),
		slog.String("Filename", realname),
		slog.Uint64("RotationInterval", rInterval),
	)

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
		if err := os.MkdirAll(realname[:j-1], 0o755); err != nil {
			logger.Warn("can't create MRT destination directory",
				slog.String("Topic", "mrt"),
				slog.String("Filename", realname),
				slog.String("Error", err.Error()),
			)
			return nil, err
		}
	}

	file, err := os.OpenFile(realname, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		logger.Warn("can't create MRT destination file",
			slog.String("Topic", "mrt"),
			slog.String("Error", err.Error()),
		)
	}
	return file, err
}

func newMrtWriter(s *BgpServer, c *oc.MrtConfig, rInterval, dInterval uint64) (*mrtWriter, error) {
	file, err := mrtFileOpen(s.logger, c.FileName, rInterval)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := mrtWriter{
		cancel:           cancel,
		s:                s,
		c:                c,
		file:             file,
		rotationInterval: rInterval,
		dumpInterval:     dInterval,
	}
	go m.loop(ctx)
	return &m, nil
}

type mrtManager struct {
	bgpServer *BgpServer
	writer    map[string]*mrtWriter
}

func (m *mrtManager) enable(c *oc.MrtConfig) error {
	if _, ok := m.writer[c.FileName]; ok {
		return fmt.Errorf("%s already exists", c.FileName)
	}

	rInterval := c.RotationInterval
	dInterval := c.DumpInterval

	setRotationMin := func() {
		if rInterval < minRotationInterval {
			m.bgpServer.logger.Info("use minimum mrt rotation interval",
				slog.String("Topic", "mrt"),
				slog.Int("Interval", minRotationInterval))
			rInterval = minRotationInterval
		}
	}

	switch c.DumpType {
	case oc.MRT_TYPE_TABLE:
		if rInterval == 0 {
			if dInterval < minDumpInterval {
				m.bgpServer.logger.Info("use minimum mrt dump interval",
					slog.String("Topic", "mrt"),
					slog.Int("Interval", minDumpInterval))
				dInterval = minDumpInterval
			}
		} else if dInterval == 0 {
			setRotationMin()
		} else {
			return fmt.Errorf("can't specify both intervals in the table dump type")
		}
	case oc.MRT_TYPE_UPDATES:
		// ignore the dump interval
		dInterval = 0
		if c.TableName.IsValid() {
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

func (m *mrtManager) disable(c *oc.MrtConfig) error {
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
