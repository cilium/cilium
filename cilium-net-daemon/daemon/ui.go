package daemon

import (
	"net"
	"time"

	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/gorilla/websocket"
)

type Conn struct {
	ws     *websocket.Conn
	uiChan chan types.UIUpdateMsg
}

func (d *Daemon) GetUIIP() (*net.TCPAddr, error) {
	_, listAddr, err := common.ParseHost(d.conf.UIServerAddr)
	return listAddr, err
}

// map[uint32]*map[uint32]*policymap.PolicyEntry where represents map[from][to]stats
type receivedStats map[uint32]*map[uint32]*policymap.PolicyEntry

func (rs receivedStats) getStats(from, to uint32) *policymap.PolicyEntry {
	fromMapPtr := rs[from]
	if fromMapPtr != nil {
		fromMap := *fromMapPtr
		pePtr := fromMap[to]
		if pePtr != nil {
			pe := policymap.PolicyEntry(*pePtr)
			return &pe
		}
	}
	return nil
}

func (d *Daemon) getReceivedStats() (receivedStats, error) {
	stats := receivedStats{}
	for _, ep := range d.endpoints {
		if ep.SecLabel != nil &&
			ep.PolicyMap != nil {

			pm, err := ep.PolicyMap.DumpToSlice()
			if err != nil {
				continue
			}

			statPtr, exists := stats[ep.SecLabel.ID]
			var stat map[uint32]*policymap.PolicyEntry
			if exists {
				stat = *statPtr
			} else {
				stat = map[uint32]*policymap.PolicyEntry{}
			}

			for _, p := range pm {
				pe, exists := stat[p.ID]
				if exists {
					pe.Add(p.PolicyEntry)
				} else {
					stat[p.ID] = &p.PolicyEntry
				}
			}
			stats[ep.SecLabel.ID] = &stat
		}
	}
	return stats, nil
}

func (d *Daemon) ListenBuildUIEvents() {
	sendToListener := func(c *Conn, message types.UIUpdateMsg) {
		select {
		case c.uiChan <- message:
		case <-time.After(time.Second * 90):
			if _, ok := d.uiListeners[c]; ok {
				delete(d.uiListeners, c)
			}
		}
	}

	go func() {
		refreshTime := time.NewTicker(2 * time.Second)
		defer refreshTime.Stop()
		for {
			select {
			case <-refreshTime.C:
				nodes := d.uiTopo.GetNodes()
				for _, fromNode := range nodes {
					sctx := &types.SearchContext{
						From: fromNode.Labels,
					}

					for _, toNode := range nodes {
						if fromNode.ID == toNode.ID {
							continue
						}
						sctx.To = toNode.Labels

						cd := d.policyCanConsume(sctx)

						stats, _ := d.getReceivedStats()

						pe := stats.getStats(uint32(fromNode.ID), uint32(toNode.ID))

						switch cd {
						case types.ALWAYS_ACCEPT, types.ACCEPT:
							d.uiTopo.AddOrUpdateEdge(fromNode.ID, toNode.ID, pe)
						default:
							d.uiTopo.DeleteEdge(fromNode.ID, toNode.ID)
						}
					}
				}
				d.uiTopo.RefreshEdges()
			}
		}
	}()

	go func() {
		for {
			select {
			case conn := <-d.registerUIListener:
				d.uiListeners[conn] = true

			case message := <-d.uiTopo.UIChan:
				for c := range d.uiListeners {
					go sendToListener(c, message)
				}
			}
		}
	}()
}

func (d *Daemon) RegisterUIListener(conn *websocket.Conn) (chan types.UIUpdateMsg, error) {
	umsg := make(chan types.UIUpdateMsg, 1)
	c := &Conn{ws: conn, uiChan: umsg}
	d.registerUIListener <- c
	return umsg, nil
}

func (d *Daemon) GetUINodes() []types.UINode {
	return d.uiTopo.GetNodes()
}

func (d *Daemon) GetUIEdges() []types.UIEdge {
	return d.uiTopo.GetEdges()
}
