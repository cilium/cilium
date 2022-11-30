package cell

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/hive/internal"
	"github.com/emicklei/dot"
	"golang.org/x/exp/slices"
)

type edge struct {
	dot.Edge
	tooltips []string
}

type dotState struct {
	g *dot.Graph

	mods  map[string]dot.Node
	edges map[string]*edge

	// provides maps from object to the module providing it
	provides map[string]string
}

func (d *dotState) populateModules(cell Cell, modId string) int {
	switch c := cell.(type) {
	case *module:
		n := 0
		for _, cell := range c.cells {
			n += d.populateModules(cell, c.id)
		}
		if n > 0 {
			// non-empty module
			//d.mods[c.id], _
			n := d.g.Node(c.id)
			n.Attr("tooltip", c.title)
			n.Attr("label", c.id+"\n"+c.title)
			n.Attr("shape", "box3d")
			n.Attr("margin", "0.2,0.1")
			d.mods[c.id] = n

		}
		return 0

	case *provider:
		n := 0
		for i := range c.ctors {
			info := c.infos[i]
			for _, output := range info.Outputs {
				o := internal.TrimName(output.String())
				d.provides[o] = modId
				n++
			}
		}
		return n

	case *invoker:
		return 1

	default:
		// hackity hack hack
		x := fmt.Sprintf("%T", c)
		if strings.Contains(x, "Config") {
			x = internal.TrimName(x)
			x = strings.TrimPrefix(x, "*cell.config[")
			x = strings.TrimSuffix(x, "]")
			d.provides[x] = modId
		}
		return 0
	}
}

func (d *dotState) populateEdges(cell Cell, modId string) {
	switch c := cell.(type) {
	case *module:
		for _, cell := range c.cells {
			d.populateEdges(cell, c.id)
		}
	case *provider:
		for i := range c.ctors {
			info := c.infos[i]
			for _, input := range info.Inputs {
				in := internal.TrimName(input.String())
				in = strings.ReplaceAll(in, "[optional]", "")
				m, ok := d.mods[modId]
				if !ok {
					log.Fatalf("d.mods[%s] is nil\n", modId)
				}
				provider := d.provides[in]
				if provider != "hive" && provider != modId {
					edgeName := modId + "<>" + provider
					e, ok := d.edges[edgeName]
					if !ok {
						e0 := d.g.Edge(m, d.mods[provider])
						e = &edge{e0, nil}
						d.edges[edgeName] = e
						e0.Attr("arrowhead", "diamond")
					}
					e.tooltips = append(e.tooltips, in)
					sort.Strings(e.tooltips)
					e.tooltips = slices.Compact(e.tooltips)
					e.Attr("tooltip", strings.Join(e.tooltips, ", "))
				}
			}
		}
	}
}

func CreateDotGraph(cells []Cell) string {
	g := dot.NewGraph(dot.Directed)

	d := dotState{g: g, edges: map[string]*edge{}, mods: map[string]dot.Node{}, provides: map[string]string{}}
	for _, c := range cells {
		d.populateModules(c, "")
	}

	// XXX fix this stuff
	d.provides["hive.Lifecycle"] = "hive"
	d.provides["logrus.FieldLogger"] = "hive"
	d.provides["hive.Shutdowner"] = "hive"

	for _, c := range cells {
		d.populateEdges(c, "")
	}

	g.Attr("rankdir", "LR")

	return g.String()
}
