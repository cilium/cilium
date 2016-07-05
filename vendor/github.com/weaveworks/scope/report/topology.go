package report

import (
	"fmt"
	"strings"
)

// Topology describes a specific view of a network. It consists of nodes and
// edges, and metadata about those nodes and edges, represented by
// EdgeMetadatas and Nodes respectively. Edges are directional, and embedded
// in the Node struct.
type Topology struct {
	Shape             string `json:"shape,omitempty"`
	Label             string `json:"label,omitempty"`
	LabelPlural       string `json:"label_plural,omitempty"`
	Nodes             `json:"nodes"`
	Controls          `json:"controls,omitempty"`
	MetadataTemplates `json:"metadata_templates,omitempty"`
	MetricTemplates   `json:"metric_templates,omitempty"`
	TableTemplates    `json:"table_templates,omitempty"`
}

// MakeTopology gives you a Topology.
func MakeTopology() Topology {
	return Topology{
		Nodes:    map[string]Node{},
		Controls: Controls{},
	}
}

// WithMetadataTemplates merges some metadata templates into this topology,
// returning a new topology.
func (t Topology) WithMetadataTemplates(other MetadataTemplates) Topology {
	return Topology{
		Shape:             t.Shape,
		Label:             t.Label,
		LabelPlural:       t.LabelPlural,
		Nodes:             t.Nodes.Copy(),
		Controls:          t.Controls.Copy(),
		MetadataTemplates: t.MetadataTemplates.Merge(other),
		MetricTemplates:   t.MetricTemplates.Copy(),
		TableTemplates:    t.TableTemplates.Copy(),
	}
}

// WithMetricTemplates merges some metadata templates into this topology,
// returning a new topology.
func (t Topology) WithMetricTemplates(other MetricTemplates) Topology {
	return Topology{
		Shape:             t.Shape,
		Label:             t.Label,
		LabelPlural:       t.LabelPlural,
		Nodes:             t.Nodes.Copy(),
		Controls:          t.Controls.Copy(),
		MetadataTemplates: t.MetadataTemplates.Copy(),
		MetricTemplates:   t.MetricTemplates.Merge(other),
		TableTemplates:    t.TableTemplates.Copy(),
	}
}

// WithTableTemplates merges some table templates into this topology,
// returning a new topology.
func (t Topology) WithTableTemplates(other TableTemplates) Topology {
	return Topology{
		Shape:             t.Shape,
		Label:             t.Label,
		LabelPlural:       t.LabelPlural,
		Nodes:             t.Nodes.Copy(),
		Controls:          t.Controls.Copy(),
		MetadataTemplates: t.MetadataTemplates.Copy(),
		MetricTemplates:   t.MetricTemplates.Copy(),
		TableTemplates:    t.TableTemplates.Merge(other),
	}
}

// WithShape sets the shape of nodes from this topology, returning a new topology.
func (t Topology) WithShape(shape string) Topology {
	return Topology{
		Shape:             shape,
		Label:             t.Label,
		LabelPlural:       t.LabelPlural,
		Nodes:             t.Nodes.Copy(),
		Controls:          t.Controls.Copy(),
		MetadataTemplates: t.MetadataTemplates.Copy(),
		MetricTemplates:   t.MetricTemplates.Copy(),
		TableTemplates:    t.TableTemplates.Copy(),
	}
}

// WithLabel sets the label terminology of this topology, returning a new topology.
func (t Topology) WithLabel(label, labelPlural string) Topology {
	return Topology{
		Shape:             t.Shape,
		Label:             label,
		LabelPlural:       labelPlural,
		Nodes:             t.Nodes.Copy(),
		Controls:          t.Controls.Copy(),
		MetadataTemplates: t.MetadataTemplates.Copy(),
		MetricTemplates:   t.MetricTemplates.Copy(),
		TableTemplates:    t.TableTemplates.Copy(),
	}
}

// AddNode adds node to the topology under key nodeID; if a
// node already exists for this key, nmd is merged with that node.
// The same topology is returned to enable chaining.
// This method is different from all the other similar methods
// in that it mutates the Topology, to solve issues of GC pressure.
func (t Topology) AddNode(node Node) Topology {
	if existing, ok := t.Nodes[node.ID]; ok {
		node = node.Merge(existing)
	}
	t.Nodes[node.ID] = node
	return t
}

// GetShape returns the current topology shape, or the default if there isn't one.
func (t Topology) GetShape() string {
	if t.Shape == "" {
		return Circle
	}
	return t.Shape
}

// Copy returns a value copy of the Topology.
func (t Topology) Copy() Topology {
	return Topology{
		Shape:             t.Shape,
		Label:             t.Label,
		LabelPlural:       t.LabelPlural,
		Nodes:             t.Nodes.Copy(),
		Controls:          t.Controls.Copy(),
		MetadataTemplates: t.MetadataTemplates.Copy(),
		MetricTemplates:   t.MetricTemplates.Copy(),
		TableTemplates:    t.TableTemplates.Copy(),
	}
}

// Merge merges the other object into this one, and returns the result object.
// The original is not modified.
func (t Topology) Merge(other Topology) Topology {
	shape := t.Shape
	if shape == "" {
		shape = other.Shape
	}
	label, labelPlural := t.Label, t.LabelPlural
	if label == "" {
		label, labelPlural = other.Label, other.LabelPlural
	}
	return Topology{
		Shape:             shape,
		Label:             label,
		LabelPlural:       labelPlural,
		Nodes:             t.Nodes.Merge(other.Nodes),
		Controls:          t.Controls.Merge(other.Controls),
		MetadataTemplates: t.MetadataTemplates.Merge(other.MetadataTemplates),
		MetricTemplates:   t.MetricTemplates.Merge(other.MetricTemplates),
		TableTemplates:    t.TableTemplates.Merge(other.TableTemplates),
	}
}

// Nodes is a collection of nodes in a topology. Keys are node IDs.
// TODO(pb): type Topology map[string]Node
type Nodes map[string]Node

// Copy returns a value copy of the Nodes.
func (n Nodes) Copy() Nodes {
	cp := make(Nodes, len(n))
	for k, v := range n {
		cp[k] = v
	}
	return cp
}

// Merge merges the other object into this one, and returns the result object.
// The original is not modified.
func (n Nodes) Merge(other Nodes) Nodes {
	cp := make(Nodes, len(n))
	for k, v := range n {
		cp[k] = v
	}
	for k, v := range other {
		if n, ok := cp[k]; ok { // don't overwrite
			cp[k] = v.Merge(n)
		} else {
			cp[k] = v
		}
	}
	return cp
}

// Validate checks the topology for various inconsistencies.
func (t Topology) Validate() error {
	errs := []string{}

	// Check all nodes are valid, and the keys are parseable, i.e.
	// contain a scope.
	for nodeID, nmd := range t.Nodes {
		if _, _, ok := ParseNodeID(nodeID); !ok {
			errs = append(errs, fmt.Sprintf("invalid node ID %q", nodeID))
		}

		// Check all adjancency keys has entries in Node.
		for _, dstNodeID := range nmd.Adjacency {
			if _, ok := t.Nodes[dstNodeID]; !ok {
				errs = append(errs, fmt.Sprintf("node missing from adjacency %q -> %q", nodeID, dstNodeID))
			}
		}

		// Check all the edge metadatas have entries in adjacencies
		nmd.Edges.ForEach(func(dstNodeID string, _ EdgeMetadata) {
			if _, ok := t.Nodes[dstNodeID]; !ok {
				errs = append(errs, fmt.Sprintf("node %s missing for edge %q", dstNodeID, nodeID))
			}
		})
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d error(s): %s", len(errs), strings.Join(errs, "; "))
	}

	return nil
}
