package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/spf13/cobra"
)

var matchPattern string

// MetricsListCmd dumps all metrics into stdout
var MetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all metrics",
	Run: func(cmd *cobra.Command, args []string) {
		res, err := client.Metrics.GetMetrics(nil)
		if err != nil {
			Fatalf("Cannot get metrics list: %s", err)
		}

		re, err := regexp.Compile(matchPattern)
		if err != nil {
			Fatalf("Cannot compile regex: %s", err)
		}

		metrics := make([]*models.Metric, 0, len(res.Payload))
		for _, metric := range res.Payload {
			if re.MatchString(metric.Name) {
				metrics = append(metrics, metric)
			}
		}

		if command.OutputJSON() {
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
	metricsCmd.AddCommand(MetricsListCmd)
	MetricsListCmd.Flags().StringVarP(&matchPattern, "match-pattern", "p", "", "Show only metrics whose names match matchpattern")
	command.AddJSONOutput(MetricsListCmd)
}
