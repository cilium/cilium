package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/spf13/cobra"
)

// MetricsListCmd dumps all metrics into stdout
var MetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all metrics",
	Run: func(cmd *cobra.Command, args []string) {
		res, err := client.Metrics.GetMetrics(nil)
		if err != nil {
			Fatalf("Cannot get metrics list: %s", err)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(res.Payload); err != nil {
				os.Exit(1)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

		fmt.Fprintln(w, "Metric\tLabels\tValue")
		for _, metric := range res.Payload {
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
		os.Exit(0)
	},
}

func init() {
	metricsCmd.AddCommand(MetricsListCmd)
	command.AddJSONOutput(MetricsListCmd)
}
