// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Args:  cobra.NoArgs,
	Short: "",
	Run:   rootCmdRun,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type Metric struct {
	Name        string
	Labels      map[string]map[string]struct{}
	Description string
	Type        string
}

var (
	promFilename     *string
	metricSeparators *[]string
	metricPrefix     *string
)

func init() {
	flags := rootCmd.Flags()
	promFilename = flags.String("prom-file", "metrics.prom", "Prom metrics file")
	metricSeparators = flags.StringSlice("metrics-separators", nil, "List of metric separators to create groups. (If there aren't enough groups a 'misc' group will be added at the end")
	metricPrefix = flags.String("metrics-prefix", "", "Remove this prefix from the metric names")
}

func rootCmdRun(cmd *cobra.Command, args []string) {
	promFile, err := os.Open(*promFilename)
	if err != nil {
		panic(fmt.Sprintf("Unable to open metrics file: %v", err))
	}
	defer promFile.Close()

	metrics := parseMetricsFromProm(promFile)

	genRSTTable(os.Stdout, metrics, *metricPrefix, *metricSeparators)
}

func genRSTTable(o io.Writer, metrics []Metric, prefix string, separators []string) {
	tableHeader := `.. list-table::
  :header-rows: 1

  * - Name
    - Labels
    - Possible Label Values
    - Description
    - Type`

	missingMetrics := printMetrics(o, metrics, prefix, separators, tableHeader)

	if len(missingMetrics) == 0 {
		return
	}
	// Print missing metrics, just a way to detect if we forgot to add a group
	// while generating the rst.
	fmt.Fprintf(o, ".. _misc:\n\nmisc\n~~~~\n")
	fmt.Fprintln(o, tableHeader)
	for _, metric := range missingMetrics {
		metricName := strings.TrimPrefix(metric.Name, prefix+"_")
		printMetric(o, metric, metricName)
	}
	fmt.Fprintf(o, "\n")
}

func printMetrics(o io.Writer, metrics []Metric, prefix string, separators []string, tableHeader string) []Metric {
	var (
		printed = map[string]struct{}{}
	)
	for _, separator := range separators {
		groupName := strings.Replace(prefix+"_"+separator, "_", "-", -1)
		fmt.Fprintf(o, ".. _%s:\n\n"+
			"``%s``\n"+
			"%s\n",
			groupName,
			separator,
			strings.Repeat("~", len(separator)+4),
		)
		fmt.Fprintln(o, tableHeader)
		for _, metric := range metrics {
			metricName := strings.TrimPrefix(metric.Name, prefix+"_"+separator+"_")
			// This metric is not part of this "group", so we will not print
			// it
			if metricName == metric.Name {
				continue
			}
			printed[metric.Name] = struct{}{}
			printMetric(o, metric, metricName)
		}
		fmt.Fprintf(o, "\n")
	}

	var (
		missingMetrics []Metric
	)
	for _, metric := range metrics {
		if _, ok := printed[metric.Name]; ok {
			continue
		}
		missingMetrics = append(missingMetrics, metric)
	}
	slices.SortFunc(missingMetrics, func(a, b Metric) int {
		return strings.Compare(a.Name, b.Name)
	})
	return missingMetrics
}

func printMetric(o io.Writer, metric Metric, metricName string) {
	const indent = 4
	if len(metric.Labels) == 0 {
		fmt.Fprintf(o,
			"  * - ``%s``\n"+
				"%*s- *None*\n"+
				"%*s- *None*\n"+
				"%*s- %s\n"+
				"%*s- %s\n",
			metricName,
			indent, "",
			indent, "",
			indent, "", metric.Description,
			indent, "", metric.Type)
		return
	}
	printMetricDescription := true

	orderedLabels := make([]string, 0, len(metric.Labels))
	for lbl := range metric.Labels {
		orderedLabels = append(orderedLabels, lbl)
	}
	slices.Sort(orderedLabels)

	for _, label := range orderedLabels {
		values := metric.Labels[label]
		printLabelName := true

		orderedValues := make([]string, 0, len(values))
		for value := range values {
			orderedValues = append(orderedValues, value)
		}
		slices.Sort(orderedValues)

		for _, value := range orderedValues {
			if printLabelName && printMetricDescription {
				fmt.Fprintf(o,
					"  * - ``%s``\n"+
						"%*s- ``%s``\n"+
						"%*s- ``%s``\n"+
						"%*s- %s\n"+
						"%*s- %s\n",
					metricName,
					indent, "", label,
					indent, "", value,
					indent, "", metric.Description,
					indent, "", metric.Type)
				printLabelName = false
				printMetricDescription = false
			} else if printLabelName {
				fmt.Fprintf(o,
					"  * - ``%s``\n"+
						"%*s- ``%s``\n"+
						"%*s- ``%s``\n"+
						"%*s-\n"+
						"%*s-\n",
					metricName,
					indent, "", label,
					indent, "", value,
					indent, "",
					indent, "")
				printLabelName = false
			} else {
				fmt.Fprintf(o,
					"  * -\n"+
						"%*s-\n"+
						"%*s- ``%s``\n"+
						"%*s-\n"+
						"%*s-\n",
					indent, "",
					indent, "", value,
					indent, "",
					indent, "")
			}
		}
	}
}

func parseMetricsFromProm(promFile io.Reader) []Metric {
	// Regular expressions
	helpRegex := regexp.MustCompile(`# HELP ([^\s]+)\s+(.+)`)
	typeRegex := regexp.MustCompile(`# TYPE ([^\s]+)\s+([^\s]+)`)
	metricRegex := regexp.MustCompile(`([^\{]+)\{([^\}]+)\}\s+([0-9\.]+)`)

	var metrics []Metric
	var currentMetric *Metric

	scanner := bufio.NewScanner(promFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Parse HELP lines
		if strings.HasPrefix(line, "# HELP") {
			matches := helpRegex.FindStringSubmatch(line)
			if len(matches) > 0 {
				// Add the previous parsed metric to the list
				if currentMetric != nil {
					metrics = append(metrics, *currentMetric)
				}
				currentMetric = &Metric{
					Name:        matches[1],
					Description: matches[2],
					Labels:      make(map[string]map[string]struct{}),
				}
			}
			continue
		}

		// Parse TYPE lines
		if strings.HasPrefix(line, "# TYPE") {
			matches := typeRegex.FindStringSubmatch(line)
			if len(matches) > 0 && currentMetric != nil && matches[1] == currentMetric.Name {
				currentMetric.Type = matches[2]
			}
			continue
		}

		// Parse metric lines
		if metricRegex.MatchString(line) {
			matches := metricRegex.FindStringSubmatch(line)
			if len(matches) > 0 {
				metricName := matches[1]
				if currentMetric == nil || metricName != currentMetric.Name {
					continue
				}
				labelsPart := matches[2]

				labels := parseLabels(labelsPart)

				for k, values := range labels {
					if currentMetric.Labels[k] == nil {
						currentMetric.Labels[k] = map[string]struct{}{}
					}
					for v := range values {
						currentMetric.Labels[k][v] = struct{}{}
					}
				}
			}
		}
	}

	// Add the previous parsed metric to the list
	if currentMetric != nil {
		metrics = append(metrics, *currentMetric)
	}
	return metrics
}

// Parse label string into a map
func parseLabels(labelsPart string) map[string]map[string]struct{} {
	labels := make(map[string]map[string]struct{})
	for pair := range strings.SplitSeq(labelsPart, ",") {
		parts := strings.Split(pair, "=")
		if len(parts) == 2 {
			if labels[parts[0]] == nil {
				labels[parts[0]] = make(map[string]struct{})
			}
			labels[parts[0]][parts[1]] = struct{}{}
		}
	}
	return labels
}
