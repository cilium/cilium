// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/hubble/pkg/defaults"
	hubprinter "github.com/cilium/cilium/hubble/pkg/printer"
	hubtime "github.com/cilium/cilium/hubble/pkg/time"
	"github.com/cilium/cilium/pkg/time"
)

var (
	selectorOpts struct {
		all          bool
		last         uint64
		since, until string
		follow       bool
		first        uint64
	}

	formattingOpts struct {
		output string

		timeFormat string

		enableIPTranslation bool
		nodeName            bool
		policyNames         bool
		numeric             bool
		color               string
	}

	otherOpts struct {
		ignoreStderr    bool
		printRawFilters bool
		inputFile       string
	}

	experimentalOpts struct {
		fieldMask       []string
		useDefaultMasks bool
	}

	printer *hubprinter.Printer

	// selector flags
	selectorFlags = pflag.NewFlagSet("selectors", pflag.ContinueOnError)
	// generic formatting flags, available to `hubble observe`, including sub-commands.
	formattingFlags = pflag.NewFlagSet("Formatting", pflag.ContinueOnError)
	// other flags
	otherFlags = pflag.NewFlagSet("other", pflag.ContinueOnError)
)

func init() {
	selectorFlags.BoolVar(&selectorOpts.all, "all", false, "Get all flows stored in Hubble's buffer. Note: this option may cause Hubble to return a lot of data. It is recommended to only use it along filters to limit the amount of data returned.")
	selectorFlags.Uint64Var(&selectorOpts.last, "last", 0, fmt.Sprintf("Get last N flows stored in Hubble's buffer (default %d). When querying against Hubble Relay, this gets N flows per instance of Hubble connected to that Relay.", defaults.FlowPrintCount))
	selectorFlags.Uint64Var(&selectorOpts.first, "first", 0, "Get first N flows stored in Hubble's buffer. When querying against Hubble Relay, this gets N flows per instance of Hubble connected to that Relay.")
	selectorFlags.BoolVarP(&selectorOpts.follow, "follow", "f", false, "Follow flows output")
	selectorFlags.StringVar(&selectorOpts.since,
		"since", "",
		fmt.Sprintf(`Filter flows since a specific date. The format is relative (e.g. 3s, 4m, 1h43,, ...) or one of:
  StampMilli:             %s
  YearMonthDay:           %s
  YearMonthDayHour:       %s
  YearMonthDayHourMinute: %s
  RFC3339:                %s
  RFC3339Milli:           %s
  RFC3339Micro:           %s
  RFC3339Nano:            %s
  RFC1123Z:               %s
 `,
			time.StampMilli,
			hubtime.YearMonthDay,
			strings.Replace(hubtime.YearMonthDayHour, "Z", "-", 1),
			strings.Replace(hubtime.YearMonthDayHourMinute, "Z", "-", 1),
			strings.Replace(time.RFC3339, "Z", "-", 1),
			strings.Replace(hubtime.RFC3339Milli, "Z", "-", 1),
			strings.Replace(hubtime.RFC3339Micro, "Z", "-", 1),
			strings.Replace(time.RFC3339Nano, "Z", "-", 1),
			strings.Replace(time.RFC1123Z, "Z", "-", 1),
		),
	)
	selectorFlags.StringVar(&selectorOpts.until,
		"until", "",
		fmt.Sprintf(`Filter flows until a specific date. The format is relative (e.g. 3s, 4m, 1h43,, ...) or one of:
  StampMilli:             %s
  YearMonthDay:           %s
  YearMonthDayHour:       %s
  YearMonthDayHourMinute: %s
  RFC3339:                %s
  RFC3339Milli:           %s
  RFC3339Micro:           %s
  RFC3339Nano:            %s
  RFC1123Z:               %s
 `,
			time.StampMilli,
			hubtime.YearMonthDay,
			strings.Replace(hubtime.YearMonthDayHour, "Z", "-", 1),
			strings.Replace(hubtime.YearMonthDayHourMinute, "Z", "-", 1),
			strings.Replace(time.RFC3339, "Z", "-", 1),
			strings.Replace(hubtime.RFC3339Milli, "Z", "-", 1),
			strings.Replace(hubtime.RFC3339Micro, "Z", "-", 1),
			strings.Replace(time.RFC3339Nano, "Z", "-", 1),
			strings.Replace(time.RFC1123Z, "Z", "-", 1),
		),
	)

	formattingFlags.StringVarP(
		&formattingOpts.output, "output", "o", "compact",
		`Specify the output format, one of:
  compact:  Compact output
  dict:     Each flow is shown as KEY:VALUE pair
  jsonpb:   JSON encoded GetFlowResponse according to proto3's JSON mapping
  json:     Alias for jsonpb
  table:    Tab-aligned columns
`)
	formattingFlags.BoolVarP(&formattingOpts.nodeName, "print-node-name", "", false, "Print node name in output")
	formattingFlags.BoolVarP(&formattingOpts.policyNames, "print-policy-names", "", false, "Print policy names in output")
	formattingFlags.StringVar(
		&formattingOpts.timeFormat, "time-format", "StampMilli",
		fmt.Sprintf(`Specify the time format for printing. This option does not apply to the json and jsonpb output type. One of:
  StampMilli:             %s
  YearMonthDay:           %s
  YearMonthDayHour:       %s
  YearMonthDayHourMinute: %s
  RFC3339:                %s
  RFC3339Milli:           %s
  RFC3339Micro:           %s
  RFC3339Nano:            %s
  RFC1123Z:               %s
 `,
			time.StampMilli,
			hubtime.YearMonthDay,
			hubtime.YearMonthDayHour,
			hubtime.YearMonthDayHourMinute,
			time.RFC3339,
			hubtime.RFC3339Milli,
			hubtime.RFC3339Micro,
			time.RFC3339Nano,
			time.RFC1123Z,
		),
	)

	otherFlags.BoolVarP(&otherOpts.ignoreStderr,
		"silent-errors", "s", false,
		"Silently ignores errors and warnings")
	otherFlags.BoolVar(&otherOpts.printRawFilters,
		"print-raw-filters", false,
		"Print allowlist/denylist filters and exit without sending the request to Hubble server")

	otherFlags.StringVar(&otherOpts.inputFile, "input-file", "",
		"Query flows from this file instead of the server. Use '-' to read from stdin.")

	otherFlags.StringSliceVar(&experimentalOpts.fieldMask, "experimental-field-mask", nil,
		"Experimental: Comma-separated list of fields for mask. Fields not in the mask will be removed from server response.")

	otherFlags.BoolVar(&experimentalOpts.useDefaultMasks, "experimental-use-default-field-masks", false,
		"Experimental: request only visible fields when the output format is compact, tab, or dict.")
}

// New observer command.
func New(vp *viper.Viper) *cobra.Command {
	observeCmd := newObserveCmd(vp)
	flowsCmd := newFlowsCmd(vp)

	observeCmd.AddCommand(
		newAgentEventsCommand(vp),
		newDebugEventsCommand(vp),
		flowsCmd,
	)

	return observeCmd
}
