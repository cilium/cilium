package report

import (
	"sort"
	"strconv"
	"strings"
)

const (
	number = "number"
)

// FromLatest and friends denote the different fields where metadata can be
// gathered from.
const (
	FromLatest   = "latest"
	FromSets     = "sets"
	FromCounters = "counters"
)

// MetadataTemplate extracts some metadata rows from a node
type MetadataTemplate struct {
	ID       string  `json:"id"`
	Label    string  `json:"label,omitempty"`    // Human-readable descriptor for this row
	Truncate int     `json:"truncate,omitempty"` // If > 0, truncate the value to this length.
	Datatype string  `json:"dataType,omitempty"`
	Priority float64 `json:"priority,omitempty"`
	From     string  `json:"from,omitempty"` // Defines how to get the value from a report node
}

// Copy returns a value-copy of the template
func (t MetadataTemplate) Copy() MetadataTemplate {
	return t
}

// MetadataRows returns the rows for a node
func (t MetadataTemplate) MetadataRows(n Node) []MetadataRow {
	from := fromDefault
	switch t.From {
	case FromLatest:
		from = fromLatest
	case FromSets:
		from = fromSets
	case FromCounters:
		from = fromCounters
	}
	if val, ok := from(n, t.ID); ok {
		if t.Truncate > 0 && len(val) > t.Truncate {
			val = val[:t.Truncate]
		}
		return []MetadataRow{{
			ID:       t.ID,
			Label:    t.Label,
			Value:    val,
			Datatype: t.Datatype,
			Priority: t.Priority,
		}}
	}
	return nil
}

func fromDefault(n Node, key string) (string, bool) {
	for _, from := range []func(n Node, key string) (string, bool){fromLatest, fromSets, fromCounters} {
		if val, ok := from(n, key); ok {
			return val, ok
		}
	}
	return "", false
}

func fromLatest(n Node, key string) (string, bool) {
	return n.Latest.Lookup(key)
}

func fromSets(n Node, key string) (string, bool) {
	val, ok := n.Sets.Lookup(key)
	return strings.Join(val, ", "), ok
}

func fromCounters(n Node, key string) (string, bool) {
	val, ok := n.Counters.Lookup(key)
	return strconv.Itoa(val), ok
}

// MetadataRow is a row for the metadata table.
type MetadataRow struct {
	ID       string  `json:"id"`
	Label    string  `json:"label"`
	Value    string  `json:"value"`
	Priority float64 `json:"priority,omitempty"`
	Datatype string  `json:"dataType,omitempty"`
}

// Copy returns a value copy of a metadata row.
func (m MetadataRow) Copy() MetadataRow {
	return m
}

// MetadataTemplates is a mergeable set of metadata templates
type MetadataTemplates map[string]MetadataTemplate

// MetadataRows returns the rows for a node
func (e MetadataTemplates) MetadataRows(n Node) []MetadataRow {
	var rows []MetadataRow
	for _, template := range e {
		rows = append(rows, template.MetadataRows(n)...)
	}
	sort.Sort(MetadataRowsByPriority(rows))
	return rows
}

// Copy returns a value copy of the metadata templates
func (e MetadataTemplates) Copy() MetadataTemplates {
	if e == nil {
		return nil
	}
	result := MetadataTemplates{}
	for k, v := range e {
		result[k] = v.Copy()
	}
	return result
}

// Merge merges two sets of MetadataTemplates so far just ignores based
// on duplicate id key
func (e MetadataTemplates) Merge(other MetadataTemplates) MetadataTemplates {
	if e == nil && other == nil {
		return nil
	}
	result := make(MetadataTemplates, len(e))
	for k, v := range e {
		result[k] = v
	}
	for k, v := range other {
		if existing, ok := result[k]; !ok || existing.Priority < v.Priority {
			result[k] = v
		}
	}
	return result
}

// MetadataRowsByPriority implements sort.Interface, so we can sort the rows by
// priority before rendering them to the UI.
type MetadataRowsByPriority []MetadataRow

// Len is part of sort.Interface.
func (m MetadataRowsByPriority) Len() int {
	return len(m)
}

// Swap is part of sort.Interface.
func (m MetadataRowsByPriority) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}

// Less is part of sort.Interface.
func (m MetadataRowsByPriority) Less(i, j int) bool {
	return m[i].Priority < m[j].Priority
}
