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

// map[uint32]map[uint32]*policymap.PolicyEntry where represents map[to][from]stats
type receivedStats map[uint32]map[uint32]*policymap.PolicyEntry

func (rs receivedStats) getStats(from, to uint32) *policymap.PolicyEntry {
	fromMap, exists := rs[to]
	if exists {
		pe, exists := fromMap[from]
		if exists && pe != nil {
			pe := policymap.PolicyEntry(*pe)
			return &pe
		}
	}
	return nil
}

func (d *Daemon) getReceivedStats() (receivedStats, error) {
	stats := receivedStats{}
	d.endpointsMU.RLock()
	for _, ep := range d.endpoints {
		if ep.SecLabel != nil {
			if ep.PolicyMap != nil {
				pm, err := ep.PolicyMap.DumpToSlice()
				if err != nil {
					continue
				}

				stat, exists := stats[ep.SecLabel.ID]
				if !exists {
					stats[ep.SecLabel.ID] = map[uint32]*policymap.PolicyEntry{}
					stat = stats[ep.SecLabel.ID]
				}

				for _, p := range pm {
					pe, exists := stat[p.ID]
					if exists {
						pe.Add(p.PolicyEntry)
					} else {
						pe := policymap.PolicyEntry(p.PolicyEntry)
						stat[p.ID] = &pe
					}
				}
			}
		}
	}
	d.endpointsMU.RUnlock()
	return stats, nil
}

func (d *Daemon) ListenBuildUIEvents() {

	go func() {
		refreshTime := time.NewTicker(2 * time.Second)
		defer refreshTime.Stop()
		for {
			select {
			case <-refreshTime.C:
				stats, _ := d.getReceivedStats()
				nodes := d.uiTopo.GetNodes()
				for _, fromNode := range nodes {
					sctx := &types.SearchContext{
						From: fromNode.Labels,
					}

					for _, toNode := range nodes {

						sctx.To = toNode.Labels

						cdReply, err := d.PolicyCanConsume(sctx)
						if err != nil {
							continue
						}
						cd := cdReply.Decision

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
				nodes := d.uiTopo.GetNodes()
				for _, node := range nodes {
					message := types.NewUIUpdateMsg().Add().Node(node).Build()
					select {
					case conn.uiChan <- message:
					default:
						delete(d.uiListeners, conn)
					}
				}
				edges := d.uiTopo.GetEdges()
				for _, edge := range edges {
					message := types.NewUIUpdateMsg().Add().Edge(edge).Build()
					select {
					case conn.uiChan <- message:
					default:
						delete(d.uiListeners, conn)
					}
				}

			case message := <-d.uiTopo.UIChan:
				for conn := range d.uiListeners {
					select {
					case conn.uiChan <- message:
					default:
						delete(d.uiListeners, conn)
					}
				}
			}
		}
	}()
}

func (d *Daemon) RegisterUIListener(conn *websocket.Conn) (chan types.UIUpdateMsg, error) {
	umsg := make(chan types.UIUpdateMsg, 256)
	c := &Conn{ws: conn, uiChan: umsg}
	d.registerUIListener <- c
	return umsg, nil
}

func (d *Daemon) AddOrUpdateUINode(id uint32, lbls []types.Label, refCount int) {
	if d.conf.IsUIEnabled() {
		d.uiTopo.AddOrUpdateNode(id, lbls, refCount)
	}
}

func (d *Daemon) DeleteUINode(id uint32) {
	if d.conf.IsUIEnabled() {
		d.uiTopo.DeleteNode(id)
	}
}
