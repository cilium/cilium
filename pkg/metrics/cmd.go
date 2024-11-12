// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
)

func newMetricsCommand(r *Registry) hive.ScriptCmdOut {
	return hive.NewScriptCmd(
		"metrics",
		script.Command(
			script.CmdUsage{
				Summary: "Show metrics",
				Args:    "[-o=file] [-format={table,yaml,json}] [match regex]",
				RegexpArgs: func(rawArgs ...string) []int {
					for i, arg := range rawArgs {
						if !strings.HasPrefix(arg, "-") {
							return []int{i}
						}
						if arg == "--" {
							return []int{i + 1}
						}
					}
					return nil
				},
				Detail: []string{
					"Lists all registered metrics.",
					"",
					"To write the metrics to a file: 'metrics -o=/path/to/file'",
					"To show metrics matching a regex: 'metrics foo.*'",
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				flags := flag.NewFlagSet("metrics", flag.ContinueOnError)
				file := flags.String("o", "", "Output file")
				format := flags.String("format", "table", "Output format, one of: table, json or yaml")
				if err := flags.Parse(args); err != nil {
					return nil, err
				}
				args = flags.Args()

				var re *regexp.Regexp
				if len(args) > 0 {
					var err error
					re, err = regexp.Compile(args[0])
					if err != nil {
						return nil, fmt.Errorf("regex: %w", err)
					}
				}

				var w io.Writer
				if *file != "" {
					f, err := os.OpenFile(s.Path(*file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
					if err != nil {
						return nil, err
					}
					w = f
					defer f.Close()
				} else {
					w = s.LogWriter()
				}
				return nil, writeMetricsFromRegistry(w, *format, re, r.inner)
			},
		),
	)
}

// getMetricValue produces a single representative value out of the metric.
func getMetricValue(name string, typ dto.MetricType, m *dto.Metric) (float64, string) {
	suffix := ""
	if strings.HasSuffix(name, "seconds") {
		suffix = "s"
	}

	switch typ {
	case dto.MetricType_COUNTER:
		v := m.Counter.GetValue()
		return v, fmt.Sprintf("%f", v)
	case dto.MetricType_GAUGE:
		v := m.Gauge.GetValue()
		return v, fmt.Sprintf("%f", v)
	case dto.MetricType_SUMMARY:
		s := m.Summary
		x := ""
		for i, q := range s.Quantile {
			x += fmt.Sprintf("p%d(%s%s)", int(100.0*(*q.Quantile)), prettyValue(*q.Value), suffix)
			if i != len(s.Quantile)-1 {
				x += " "
			}
		}
		return 0.0, x

	case dto.MetricType_HISTOGRAM:
		count := m.Histogram.GetSampleCountFloat()
		var avg float64
		if count > 0.0 {
			avg = m.Histogram.GetSampleSum() / count
		}
		return avg, prettyValue(avg)
	default:
		return -1, fmt.Sprintf("(?%s)", typ)
	}
}

func writeMetricsFromRegistry(w io.Writer, format string, re *regexp.Regexp, reg *prometheus.Registry) error {
	metrics, err := reg.Gather()
	if err != nil {
		return fmt.Errorf("gather: %w", err)
	}

	var (
		// Since Gather() collects the metrics in unsorted order, we need
		// to collect the lines we want to write and then sort them.
		lines []string

		jsonMetrics []models.Metric
	)

	for _, val := range metrics {
		metricName := val.GetName()
		metricType := val.GetType()

		for _, metric := range val.Metric {
			value, valueS := getMetricValue(metricName, metricType, metric)
			label := joinLabels(metric.GetLabel())
			if re != nil && !re.MatchString(metricName+label) {
				continue
			}
			if format == "table" {
				lines = append(lines, fmt.Sprintf("%s\t%s\t%s\n", metricName, label, valueS))
			} else {
				jsonMetrics = append(jsonMetrics,
					models.Metric{
						Name:   metricName,
						Labels: labelsMap(metric.GetLabel()),
						Value:  value,
					})
			}
		}
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonMetrics)
	case "yaml":
		enc := yaml.NewEncoder(w)
		return enc.Encode(jsonMetrics)
	default:
		sort.Strings(lines)

		tw := tabwriter.NewWriter(w, 5, 0, 3, ' ', 0)
		defer tw.Flush()
		if _, err := fmt.Fprintln(tw, "Metric\tLabels\tValue"); err != nil {
			return err
		}
		for _, l := range lines {
			_, err := tw.Write([]byte(l))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func joinLabels(labels []*dto.LabelPair) string {
	var b strings.Builder
	for i, lp := range labels {
		b.WriteString(lp.GetName())
		b.WriteByte('=')
		b.WriteString(lp.GetValue())
		if i < len(labels)-1 {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func labelsMap(labels []*dto.LabelPair) map[string]string {
	m := map[string]string{}
	for _, lp := range labels {
		m[lp.GetName()] = lp.GetValue()
	}
	return m
}

func prettyValue(v float64) string {
	unit, multp := chooseUnit(v)
	return fmt.Sprintf("%.4g%s", v*multp, unit)
}

func chooseUnit(v float64) (string, float64) {
	unit := ""
	multp := 1.0
	v = math.Abs(v)
	switch {
	case v == 0.0:
	case v > 1_000_000_000_000:
		unit = "T"
		multp = 0.000_000_000_001
	case v > 1_000_000_000:
		unit = "G"
		multp = 0.000_000_001
	case v > 1_000_000:
		unit = "M"
		multp = 0.000_001
	case v > 1000:
		unit = "k"
		multp = 0.001
	case v < 0.000_000_001:
		unit = "p"
		multp = 1_000_000_000_000
	case v < 0.000_001:
		unit = "n"
		multp = 1_000_000_000
	case v < 0.001:
		unit = "µ"
		multp = 1_000_000
	case v < 1:
		unit = "m"
		multp = 1000
	}
	return unit, multp
}
