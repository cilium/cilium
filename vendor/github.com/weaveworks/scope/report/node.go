package report

import (
	"time"

	"github.com/weaveworks/scope/common/mtime"
)

// Node describes a superset of the metadata that probes can collect about a
// given node in a given topology, along with the edges emanating from the
// node and metadata about those edges.
type Node struct {
	ID             string                   `json:"id,omitempty"`
	Topology       string                   `json:"topology,omitempty"`
	Counters       Counters                 `json:"counters,omitempty"`
	Sets           Sets                     `json:"sets,omitempty"`
	Adjacency      IDList                   `json:"adjacency"`
	Edges          EdgeMetadatas            `json:"edges,omitempty"`
	Controls       NodeControls             `json:"controls,omitempty"`
	LatestControls NodeControlDataLatestMap `json:"latestControls,omitempty"`
	Latest         StringLatestMap          `json:"latest,omitempty"`
	Metrics        Metrics                  `json:"metrics,omitempty"`
	Parents        Sets                     `json:"parents,omitempty"`
	Children       NodeSet                  `json:"children,omitempty"`
}

// MakeNode creates a new Node with no initial metadata.
func MakeNode(id string) Node {
	return Node{
		ID:             id,
		Counters:       EmptyCounters,
		Sets:           EmptySets,
		Adjacency:      EmptyIDList,
		Edges:          EmptyEdgeMetadatas,
		Controls:       MakeNodeControls(),
		LatestControls: EmptyNodeControlDataLatestMap,
		Latest:         EmptyStringLatestMap,
		Metrics:        Metrics{},
		Parents:        EmptySets,
	}
}

// MakeNodeWith creates a new Node with the supplied map.
func MakeNodeWith(id string, m map[string]string) Node {
	return MakeNode(id).WithLatests(m)
}

// WithID returns a fresh copy of n, with ID changed.
func (n Node) WithID(id string) Node {
	n.ID = id
	return n
}

// WithTopology returns a fresh copy of n, with ID changed.
func (n Node) WithTopology(topology string) Node {
	n.Topology = topology
	return n
}

// Before is used for sorting nodes by topology and id
func (n Node) Before(other Node) bool {
	return n.Topology < other.Topology || (n.Topology == other.Topology && n.ID < other.ID)
}

// Equal is used for comparing nodes by topology and id
func (n Node) Equal(other Node) bool {
	return n.Topology == other.Topology && n.ID == other.ID
}

// After is used for sorting nodes by topology and id
func (n Node) After(other Node) bool {
	return other.Topology < n.Topology || (other.Topology == n.Topology && other.ID < n.ID)
}

// WithLatests returns a fresh copy of n, with Metadata m merged in.
func (n Node) WithLatests(m map[string]string) Node {
	ts := mtime.Now()
	for k, v := range m {
		n.Latest = n.Latest.Set(k, ts, v)
	}
	return n
}

// WithLatest produces a new Node with k mapped to v in the Latest metadata.
func (n Node) WithLatest(k string, ts time.Time, v string) Node {
	n.Latest = n.Latest.Set(k, ts, v)
	return n
}

// WithCounters returns a fresh copy of n, with Counters c merged in.
func (n Node) WithCounters(c map[string]int) Node {
	n.Counters = n.Counters.Merge(Counters{}.fromIntermediate(c))
	return n
}

// WithSet returns a fresh copy of n, with set merged in at key.
func (n Node) WithSet(key string, set StringSet) Node {
	n.Sets = n.Sets.Add(key, set)
	return n
}

// WithSets returns a fresh copy of n, with sets merged in.
func (n Node) WithSets(sets Sets) Node {
	n.Sets = n.Sets.Merge(sets)
	return n
}

// WithMetric returns a fresh copy of n, with metric merged in at key.
func (n Node) WithMetric(key string, metric Metric) Node {
	n.Metrics = n.Metrics.Copy()
	n.Metrics[key] = n.Metrics[key].Merge(metric)
	return n
}

// WithMetrics returns a fresh copy of n, with metrics merged in.
func (n Node) WithMetrics(metrics Metrics) Node {
	n.Metrics = n.Metrics.Merge(metrics)
	return n
}

// WithAdjacent returns a fresh copy of n, with 'a' added to Adjacency
func (n Node) WithAdjacent(a ...string) Node {
	n.Adjacency = n.Adjacency.Add(a...)
	return n
}

// WithEdge returns a fresh copy of n, with 'dst' added to Adjacency and md
// added to EdgeMetadata.
func (n Node) WithEdge(dst string, md EdgeMetadata) Node {
	n.Adjacency = n.Adjacency.Add(dst)
	n.Edges = n.Edges.Add(dst, md)
	return n
}

// WithControls returns a fresh copy of n, with cs added to Controls.
func (n Node) WithControls(cs ...string) Node {
	n.Controls = n.Controls.Add(cs...)
	return n
}

// WithLatestActiveControls returns a fresh copy of n, with active controls cs added to LatestControls.
func (n Node) WithLatestActiveControls(cs ...string) Node {
	lcs := map[string]NodeControlData{}
	for _, control := range cs {
		lcs[control] = NodeControlData{}
	}
	return n.WithLatestControls(lcs)
}

// WithLatestControls returns a fresh copy of n, with lcs added to LatestControls.
func (n Node) WithLatestControls(lcs map[string]NodeControlData) Node {
	ts := mtime.Now()
	for k, v := range lcs {
		n.LatestControls = n.LatestControls.Set(k, ts, v)
	}
	return n
}

// WithLatestControl produces a new Node with control added to it
func (n Node) WithLatestControl(control string, ts time.Time, data NodeControlData) Node {
	n.LatestControls = n.LatestControls.Set(control, ts, data)
	return n
}

// WithParents returns a fresh copy of n, with sets merged in.
func (n Node) WithParents(parents Sets) Node {
	n.Parents = n.Parents.Merge(parents)
	return n
}

// PruneParents returns a fresh copy of n, without any parents.
func (n Node) PruneParents() Node {
	n.Parents = EmptySets
	return n
}

// WithChildren returns a fresh copy of n, with children merged in.
func (n Node) WithChildren(children NodeSet) Node {
	n.Children = n.Children.Merge(children)
	return n
}

// WithChild returns a fresh copy of n, with one child merged in.
func (n Node) WithChild(child Node) Node {
	n.Children = n.Children.Merge(MakeNodeSet(child))
	return n
}

// Merge mergses the individual components of a node and returns a
// fresh node.
func (n Node) Merge(other Node) Node {
	id := n.ID
	if id == "" {
		id = other.ID
	}
	topology := n.Topology
	if topology == "" {
		topology = other.Topology
	} else if other.Topology != "" && topology != other.Topology {
		panic("Cannot merge nodes with different topology types: " + topology + " != " + other.Topology)
	}
	return Node{
		ID:             id,
		Topology:       topology,
		Counters:       n.Counters.Merge(other.Counters),
		Sets:           n.Sets.Merge(other.Sets),
		Adjacency:      n.Adjacency.Merge(other.Adjacency),
		Edges:          n.Edges.Merge(other.Edges),
		Controls:       n.Controls.Merge(other.Controls),
		LatestControls: n.LatestControls.Merge(other.LatestControls),
		Latest:         n.Latest.Merge(other.Latest),
		Metrics:        n.Metrics.Merge(other.Metrics),
		Parents:        n.Parents.Merge(other.Parents),
		Children:       n.Children.Merge(other.Children),
	}
}
