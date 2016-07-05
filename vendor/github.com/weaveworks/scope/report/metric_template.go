package report

import (
	"math"
	"sort"
)

// MetricTemplate extracts a metric row from a node
type MetricTemplate struct {
	ID       string  `json:"id"`
	Label    string  `json:"label,omitempty"`
	Format   string  `json:"format,omitempty"`
	Group    string  `json:"group,omitempty"`
	Priority float64 `json:"priority,omitempty"`
}

// MetricRows returns the rows for a node
func (t MetricTemplate) MetricRows(n Node) []MetricRow {
	metric, ok := n.Metrics.Lookup(t.ID)
	if !ok {
		return nil
	}
	row := MetricRow{
		ID:       t.ID,
		Label:    t.Label,
		Format:   t.Format,
		Group:    t.Group,
		Priority: t.Priority,
		Metric:   &metric,
	}
	if s, ok := metric.LastSample(); ok {
		row.Value = toFixed(s.Value, 2)
	}
	return []MetricRow{row}
}

// Copy returns a value-copy of the metric template
func (t MetricTemplate) Copy() MetricTemplate {
	return t
}

// MetricTemplates is a mergeable set of metric templates
type MetricTemplates map[string]MetricTemplate

// MetricRows returns the rows for a node
func (e MetricTemplates) MetricRows(n Node) []MetricRow {
	var rows []MetricRow
	for _, template := range e {
		rows = append(rows, template.MetricRows(n)...)
	}
	sort.Sort(MetricRowsByPriority(rows))
	return rows
}

// Copy returns a value copy of the metadata templates
func (e MetricTemplates) Copy() MetricTemplates {
	if e == nil {
		return nil
	}
	result := MetricTemplates{}
	for k, v := range e {
		result[k] = v.Copy()
	}
	return result
}

// Merge merges two sets of MetricTemplates so far just ignores based
// on duplicate id key
func (e MetricTemplates) Merge(other MetricTemplates) MetricTemplates {
	if e == nil && other == nil {
		return nil
	}
	result := make(MetricTemplates, len(e))
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

// toFixed truncates decimals of float64 down to specified precision
func toFixed(num float64, precision int) float64 {
	output := math.Pow(10, float64(precision))
	return float64(int64(num*output)) / output
}
