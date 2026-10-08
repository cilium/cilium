// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/go-openapi/strfmt"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/operator/client"
	metricsApi "github.com/cilium/cilium/api/v1/operator/client/metrics"
	"github.com/cilium/cilium/api/v1/operator/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/logging"
)

var (
	matchPattern string
	operatorAddr string
)

// defaultOperatorAddrs are the addresses tried, in order, when
// --server-address is not given.
var defaultOperatorAddrs = []string{"127.0.0.1:9234", "[::1]:9234"}

// getMetrics retrieves the operator metrics from the first of addrs that
// answers, and reports the errors of every attempt if none does.
func getMetrics(addrs []string) ([]*models.Metric, error) {
	var errs []error
	for _, addr := range addrs {
		c := client.NewHTTPClientWithConfig(
			strfmt.Default, client.DefaultTransportConfig().WithHost(addr))

		res, err := c.Metrics.GetMetrics(metricsApi.NewGetMetricsParams())
		if err == nil {
			return res.Payload, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", addr, err))
	}
	return nil, errors.Join(errs...)
}

// MetricsListCmd dumps all metrics into stdout
var MetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all metrics for the operator",
	Run: func(cmd *cobra.Command, args []string) {
		// slogloggercheck: use the logger with the default settings since this ist only used for CLI output
		logger := logging.DefaultSlogLogger

		addrs := defaultOperatorAddrs
		if operatorAddr != "" {
			addrs = []string{operatorAddr}
		}

		payload, err := getMetrics(addrs)
		if err != nil {
			logging.Fatal(logger, fmt.Sprintf("Cannot get metrics list: %s", err))
		}

		re, err := regexp.Compile(matchPattern)
		if err != nil {
			logging.Fatal(logger, fmt.Sprintf("Cannot compile regex: %s", err))
		}

		metrics := make([]*models.Metric, 0, len(payload))
		for _, metric := range payload {
			if re.MatchString(metric.Name) {
				metrics = append(metrics, metric)
			}
		}

		if command.OutputOption() {
			if err := command.PrintOutput(metrics); err != nil {
				os.Exit(1)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

		fmt.Fprintln(w, "Metric\tLabels\tValue")
		for _, metric := range metrics {
			label := ""
			if len(metric.Labels) > 0 {
				labelArray := []string{}
				for key, value := range metric.Labels {
					labelArray = append(labelArray, fmt.Sprintf(`%s="%s"`, key, value))
				}
				label = strings.Join(labelArray, " ")
			}
			fmt.Fprintf(w, "%s\t%s\t%f\n", metric.Name, label, metric.Value)
		}
		w.Flush()
	},
}

func init() {
	MetricsListCmd.Flags().StringVarP(&matchPattern, "match-pattern", "p", "", "Show only metrics whose names match matchpattern")
	MetricsListCmd.Flags().StringVarP(&operatorAddr, "server-address", "s", "", fmt.Sprintf("Address of the operator API server (default %s)", strings.Join(defaultOperatorAddrs, " or ")))
	command.AddOutputOption(MetricsListCmd)
}
