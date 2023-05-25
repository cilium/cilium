// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/internal/vitals"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	jsonFmt = "json"
	yamlFmt = "yaml"
	spacer  = "  "
)

var hLogo = []string{
	`          `,
	`/¯¯\__/¯¯\`,
	`\__/  \__/`,
	`/¯¯\__/¯¯\`,
	`\__/  \__/`,
	`          `,
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Display daemon modules health status",
	RunE:  runHealth,
}

func init() {
	rootCmd.AddCommand(healthCmd)
	command.AddOutputOption(healthCmd)
}

func header(w io.Writer, l int, t vitals.Tally) {
	c := vitals.HealthScoreColor(t.Score())
	var (
		tab  = strings.Repeat(spacer, 2)
		fmat = tab + "%-10s: %d\n"
	)
	for i, s := range hLogo {
		if l == 0 {
			color.FgDefault.Print(s)
		} else {
			c.Print(s)
		}
		switch i {
		case 1:
			fmt.Printf("%sCilium Health\n", tab)
		case 2:
			fmt.Printf("%s%-10s: %s\n", tab, "Node:", os.Getenv("HOSTNAME"))
		case 3:
			vitals.LevelColor(cell.LevelDegraded).Printf(fmat, "Degraded:", t.DegradedCount())
		case 4:
			vitals.LevelColor(cell.LevelDown).Printf(fmat, "Down:", t.DownCount())
		default:
			fmt.Println()
		}
	}
	fmt.Println()
}

func runHealth(cmd *cobra.Command, args []string) error {
	resp, err := client.Daemon.GetHealth(daemon.NewGetHealthParams())
	if err != nil {
		return err
	}
	fmt, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	return dump(os.Stdout, resp, fmt)
}

func dump(w io.Writer, resp *daemon.GetHealthOK, fmat string) error {
	switch fmat {
	case jsonFmt:
		raw, err := json.Marshal(resp.Payload)
		if err != nil {
			return err
		}
		fmt.Fprint(w, string(raw))
	case yamlFmt:
		raw, err := yaml.Marshal(resp.Payload)
		if err != nil {
			return err
		}
		fmt.Fprint(w, string(raw))
	default:
		color.SetOutput(w)
		header(w, len(resp.Payload.Modules), vitals.NewTally((resp.Payload)))
		for _, m := range resp.Payload.Modules {
			c := vitals.LevelColor(cell.Level(m.Level))
			c.Printf("%s· %s %-20s (%s)\n", spacer, vitals.ScoreIcon(cell.Level(m.Level)), m.ModuleID, m.LastUpdated)
			vitals.MsgColor.Printf("%s· %s\n", strings.Repeat(spacer, 3), m.Message)
		}
	}

	return nil
}
