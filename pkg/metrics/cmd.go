// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"maps"
	"math"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/api/v1/models"
)

func metricsCommands(r *Registry, dc *sampler) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"metrics":      metricsCommand(r, dc),
		"metrics/plot": plotCommand(dc),
		"metrics/html": htmlCommand(dc),
	})
}

// metricsCommand implements the "metrics" script command. This can be accessed
// in script tests, via "cilium-dbg shell" or indirectly via 'cilium-dbg metrics list'.
func metricsCommand(r *Registry, dc *sampler) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List registered metrics",
			Args:    "[match regex]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("out", "o", "", "Output file")
				fs.BoolP("sampled", "s", false, "Show sampled metrics")
				fs.StringP("format", "f", "table", "Output format, one of: table, json or yaml")
			},
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
				"To write the metrics to a file: 'metrics --out=/path/to/file'",
				"To show metrics matching a regex: 'metrics foo.*'",
				"To show samples from last 60 minutes: 'metrics --sampled'",
				"",
				"The metric samples can be plotted with 'metrics/plot' command.",
				"",
				"Run 'metrics -h' for extended help of the flags.",
				"",
				"Metrics can be filtered with a regexp. The match is made",
				"against the metric name and its labels.",
				"For example 'metrics regen.*scope=total' would match the",
				"regenerations metric with one of the labels being scope=total",
				"",
				"In the sample output the 50th, 90th and 99th quantiles are shown",
				"for histograms, e.g. in '15ms / 30ms / 60ms' 50th is 15ms and so on.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			file, err := s.Flags.GetString("out")
			if err != nil {
				return nil, err
			}
			sampled, err := s.Flags.GetBool("sampled")
			if err != nil {
				return nil, err
			}
			format, err := s.Flags.GetString("format")
			if err != nil {
				return nil, err
			}
			var re *regexp.Regexp
			if len(args) > 0 {
				var err error
				re, err = regexp.Compile(args[0])
				if err != nil {
					return nil, fmt.Errorf("regex: %w", err)
				}
			}

			var w io.Writer
			if file != "" {
				f, err := os.OpenFile(s.Path(file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					return nil, err
				}
				w = f
				defer f.Close()
			} else {
				w = s.LogWriter()
			}

			if sampled {
				return nil, writeMetricsFromSamples(w, format, re, dc)
			}

			return nil, writeMetricsFromRegistry(w, format, re, r.inner)
		},
	)
}

// plotCommand implements the "metrics/plot" script command. This can be accessed
// in script tests, via "cilium-dbg shell" or indirectly via 'cilium-dbg metrics list'.
func plotCommand(dc *sampler) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Plot sampled metrics as a line graph",
			Args:    "[match regex]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("out", "o", "", "Output file")
				fs.Bool("rate", false, "Plot the rate of change")
			},
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
				"The sampled metric is specified with the regex argument.",
				"Both the metric name and its labels are matched against.",
				"Use the 'metrics' command to search for the right regex.",
				"",
				"For example to plot the 'go_sched_latencies_seconds':",
				"",
				"cilium> metrics/plot go_sched_lat",
				"",
				"Or to plot the sysctl reconciliation durations:",
				"",
				"cilium> metrics/plot reconciler_duration.*sysctl",
				"",
				"Specify '-rate' to show the rate of change for a counter,",
				"for example to plot how many bytes are allocated per minute:",
				"",
				"cilium> metrics/plot -rate go.*heap_alloc_bytes",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			s.Logf("args: %v\n", args)

			file, err := s.Flags.GetString("out")
			if err != nil {
				return nil, err
			}
			rate, err := s.Flags.GetBool("rate")
			if err != nil {
				return nil, err
			}
			var re *regexp.Regexp
			if len(args) > 0 {
				var err error
				re, err = regexp.Compile(args[0])
				if err != nil {
					return nil, fmt.Errorf("regex: %w", err)
				}
			}

			var w io.Writer
			if file != "" {
				f, err := os.OpenFile(s.Path(file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					return nil, err
				}
				w = f
				defer f.Close()
			} else {
				w = s.LogWriter()
			}

			dc.mu.Lock()
			defer dc.mu.Unlock()

			if re == nil {
				fmt.Fprintln(w, "regexp needed to find metric")
				return nil, nil
			}

			sampledMetrics := slices.Collect(maps.Values(dc.metrics))
			slices.SortFunc(sampledMetrics, func(a, b debugSamples) int {
				return cmp.Or(
					cmp.Compare(a.getName(), b.getName()),
					cmp.Compare(a.getLabels(), b.getLabels()),
				)
			})

			var ds debugSamples
			matched := true
			for _, ds = range sampledMetrics {
				matched = re.MatchString(ds.getName() + ds.getLabels())
				if matched {
					break
				}
			}
			if !matched {
				fmt.Fprintf(w, "no metric found matching regexp %q", re.String())
				return nil, nil
			}

			switch ds := ds.(type) {
			case *gaugeOrCounterSamples:
				PlotSamples(w, rate, ds.getName(), ds.getLabels(), samplingTimeSpan, ds.samples.grab(), ds.bits)
			case *histogramSamples:
				PlotSamples(w, rate, ds.getName()+" (p50)", ds.getLabels(), samplingTimeSpan, ds.p50.grab(), ds.bits)
				fmt.Fprintln(w)
				PlotSamples(w, rate, ds.getName()+" (p90)", ds.getLabels(), samplingTimeSpan, ds.p90.grab(), ds.bits)
				fmt.Fprintln(w)
				PlotSamples(w, rate, ds.getName()+" (p99)", ds.getLabels(), samplingTimeSpan, ds.p99.grab(), ds.bits)
			}

			return nil, nil
		},
	)
}

//go:embed dump.html.tmpl
var htmlTemplate string

func htmlCommand(dc *sampler) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Produce a HTML file from the sampled metrics",
			Args:    "",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("out", "o", "", "Output file")
			},
			Detail: []string{},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			file, err := s.Flags.GetString("out")
			if err != nil {
				return nil, err
			}
			var w io.Writer
			if file != "" {
				f, err := os.OpenFile(s.Path(file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					return nil, err
				}
				w = f
				defer f.Close()
			} else {
				w = s.LogWriter()
			}

			dc.mu.Lock()
			defer dc.mu.Unlock()

			dump := JSONSampleDump{
				NumSamples:      numSamples,
				IntervalSeconds: int(samplingInterval.Seconds()),
			}
			for _, ds := range dc.metrics {
				dump.Samples = append(dump.Samples, ds.getJSON())
			}
			slices.SortFunc(dump.Samples, func(a, b JSONSamples) int {
				return cmp.Or(
					cmp.Compare(a.Name, b.Name),
					cmp.Compare(a.Labels, b.Labels),
				)
			})

			tmpl, err := template.New("metrics.html").Parse(htmlTemplate)
			if err != nil {
				return nil, err
			}
			return nil, tmpl.Execute(w, &dump)
		},
	)
}

func writeMetricsFromSamples(outw io.Writer, format string, re *regexp.Regexp, dc *sampler) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	sampledMetrics := slices.Collect(maps.Values(dc.metrics))
	slices.SortFunc(sampledMetrics, func(a, b debugSamples) int {
		return cmp.Or(
			cmp.Compare(a.getName(), b.getName()),
			cmp.Compare(a.getLabels(), b.getLabels()),
		)
	})

	switch format {
	case "json", "yaml":
		dump := JSONSampleDump{
			NumSamples:      numSamples,
			IntervalSeconds: int(samplingInterval.Seconds()),
		}
		for _, ds := range sampledMetrics {
			if re != nil && !re.MatchString(ds.getName()+ds.getLabels()) {
				continue
			}
			dump.Samples = append(dump.Samples, ds.getJSON())
		}
		if format == "json" {
			enc := json.NewEncoder(outw)
			enc.SetIndent("", "  ")
			return enc.Encode(dump)
		} else {
			enc := yaml.NewEncoder(outw)
			return enc.Encode(dump)
		}
	case "table":
		w := tabwriter.NewWriter(outw, 5, 0, 3, ' ', 0)
		defer w.Flush()
		_, err := fmt.Fprintln(w, "Metric\tLabels\t5min\t30min\t60min\t120min")
		if err != nil {
			return err
		}
		for _, ds := range sampledMetrics {
			if re != nil && !re.MatchString(ds.getName()+ds.getLabels()) {
				continue
			}
			m5, m30, m60, m120 := ds.get()
			_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", ds.getName(), ds.getLabels(), m5, m30, m60, m120)
			if err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q", format)
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
	case "table":
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
		return nil
	default:
		return fmt.Errorf("unknown format %q", format)
	}
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
		b := convertHistogram(m.Histogram)
		p50 := getHistogramQuantile(b, 0.50)
		p90 := getHistogramQuantile(b, 0.90)
		p99 := getHistogramQuantile(b, 0.99)
		return p90, fmt.Sprintf("%s%s / %s%s / %s%s",
			prettyValue(p50), suffix, prettyValue(p90), suffix, prettyValue(p99), suffix)
	default:
		return -1, fmt.Sprintf("(?%s)", typ)
	}
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
