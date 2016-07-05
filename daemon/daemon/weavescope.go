package daemon

import (
	//"strconv"

	"github.com/weaveworks/scope/common/xfer"
	"github.com/weaveworks/scope/report"
)

var weaveRep report.Report

func init() {
	weaveRep = report.MakeReport()
	ps := xfer.PluginSpec{
		ID:          "cilium",
		Label:       "cilium",
		Description: "Gets net IO statistics",
		Interfaces:  []string{"reporter"},
		APIVersion:  "1",
	}
	weaveRep.Plugins.Add(ps)
	//weaveRep.Host.MetricTemplates = report.MetricTemplates{}
	//weaveRep.Host.MetricTemplates["cilium"] = report.MetricTemplate{
	//      ID:       "cilium-net-stat",
	//      Label:    "cilium-net-stat-1",
	//      Format:   report.IntegerFormat,
	//      Priority: 0.1,
	//}
}

func (d *Daemon) WeaveScopeReport() (*report.Report, error) {
	//for _, ep := range d.endpoints {
	//      if _, ok := weaveRep.Host.Nodes[ep.ID]; !ok {
	//              weaveRep.Host.Nodes[ep.ID] = report.MakeNode(ep.ID)
	//      }
	//      pmap, err := ep.PolicyMap.DumpToSlice()
	//      if err != nil {
	//              continue
	//      }
	//      getID := func(id uint32, str string) string {
	//              return strconv.FormatUint(uint64(id), 10) + str
	//      }
	//      for _, pe := range pmap {
	//              rBytesID := getID(pe.ID, "-recv-bytes")
	//              weaveRep.Host.Nodes[ep.ID].Counters.Add(rBytesID, int(pe.Bytes))
	//              //if _, ok := weaveRep.Host.Nodes[ep.ID].Metrics[rBytesID]; !ok {
	//              //      weaveRep.Host.Nodes[ep.ID].Metrics[rBytesID] = report.MakeMetric()
	//              //}
	//              //weaveRep.Host.Nodes[ep.ID].Metrics[rBytesID].Add(time.Now(), float64(pe.Bytes))
	//              //
	//              rPacketsID := getID(pe.ID, "-recv-packets")
	//              weaveRep.Host.Nodes[ep.ID].Counters.Add(rPacketsID, int(pe.Packets))
	//              //if _, ok := weaveRep.Host.Nodes[ep.ID].Metrics[rPacketsID]; !ok {
	//              //      weaveRep.Host.Nodes[ep.ID].Metrics[rPacketsID] = report.MakeMetric()
	//              //}
	//              //weaveRep.Host.Nodes[ep.ID].Metrics[rPacketsID].Add(time.Now(), float64(pe.Packets))
	//      }
	//}
	return &weaveRep, nil
}
