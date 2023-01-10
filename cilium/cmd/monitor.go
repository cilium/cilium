// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/format"
	"github.com/cilium/cilium/pkg/monitor/payload"
)

const (
	connTimeout = 12 * time.Second
)

// monitorCmd represents the monitor command
var (
	monitorCmd = &cobra.Command{
		Use:   "monitor",
		Short: "Display BPF program events",
		Long: `The monitor displays notifications and events emitted by the BPF
programs attached to endpoints and devices. This includes:
  * Dropped packet notifications
  * Captured packet traces
  * Policy verdict notifications
  * Debugging information`,
		Run: func(cmd *cobra.Command, args []string) {
			runMonitor(args)
		},
	}
	linkCache  = link.NewLinkCache()
	printer    = format.NewMonitorFormatter(format.INFO, linkCache)
	socketPath = ""
	verbosity  = []bool{}
)

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().BoolVar(&printer.Hex, "hex", false, "Do not dissect, print payload in HEX")
	monitorCmd.Flags().VarP(&printer.EventTypes, "type", "t", fmt.Sprintf("Filter by event types %v", monitor.GetAllTypes()))
	monitorCmd.Flags().Var(&printer.FromSource, "from", "Filter by source endpoint id")
	monitorCmd.Flags().Var(&printer.ToDst, "to", "Filter by destination endpoint id")
	monitorCmd.Flags().Var(&printer.Related, "related-to", "Filter by either source or destination endpoint id")
	monitorCmd.Flags().BoolSliceVarP(&verbosity, "verbose", "v", nil, "Enable verbose output (-v, -vv)")
	monitorCmd.Flags().Lookup("verbose").NoOptDefVal = "false"
	monitorCmd.Flags().BoolVarP(&printer.JSONOutput, "json", "j", false, "Enable json output. Shadows -v flag")
	monitorCmd.Flags().BoolVarP(&printer.Numeric, "numeric", "n", false, "Display all security identities as numeric values")
	monitorCmd.Flags().StringVar(&socketPath, "monitor-socket", "", "Configure monitor socket path")
	vp.BindEnv("monitor-socket", "CILIUM_MONITOR_SOCK")
	vp.BindPFlags(monitorCmd.Flags())
}

func setVerbosity() {
	if printer.JSONOutput {
		printer.Verbosity = format.JSON
	} else {
		switch len(verbosity) {
		case 1:
			printer.Verbosity = format.DEBUG
		case 2:
			printer.Verbosity = format.VERBOSE
		default:
			printer.Verbosity = format.INFO
		}
	}
}

func setupSigHandler() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for range signalChan {
			fmt.Fprintf(os.Stderr, "\nReceived an interrupt, disconnecting from monitor...\n\n")
			os.Exit(0)
		}
	}()
}

// openMonitorSock attempts to open a version specific monitor socket It
// returns a connection, with a version, or an error.
func openMonitorSock(path string) (conn net.Conn, version listener.Version, err error) {
	errors := make([]string, 0)

	// try the user-provided socket
	if path != "" {
		conn, err = net.Dial("unix", path)
		if err == nil {
			version = listener.Version1_2
			return conn, version, nil
		}
		errors = append(errors, path+": "+err.Error())
	}

	// try the 1.2 socket
	conn, err = net.Dial("unix", defaults.MonitorSockPath1_2)
	if err == nil {
		return conn, listener.Version1_2, nil
	}
	errors = append(errors, defaults.MonitorSockPath1_2+": "+err.Error())

	return nil, listener.VersionUnsupported, fmt.Errorf("Cannot find or open a supported node-monitor socket. %s", strings.Join(errors, ","))
}

// consumeMonitorEvents handles and prints events on a monitor connection. It
// calls getMonitorParsed to construct a monitor-version appropriate parser.
// It closes conn on return, and returns on error, including io.EOF
func consumeMonitorEvents(conn net.Conn, version listener.Version) error {
	defer conn.Close()

	getParsedPayload, err := getMonitorParser(conn, version)
	if err != nil {
		return err
	}

	for {
		pl, err := getParsedPayload()
		if err != nil {
			return err
		}
		if !printer.FormatEvent(pl) {
			// earlier code used an else to handle this case, along with pl.Type ==
			// payload.RecordLost above. It should be safe to call lostEvent to match
			// the earlier behaviour, despite it not being wholly correct.
			log.WithError(err).WithField("type", pl.Type).Warn("Unknown payload type")
			format.LostEvent(pl.Lost, pl.CPU)
		}
	}
}

// eventParseFunc is a convenience function type used as a version-specific
// parser of monitor events
type eventParserFunc func() (*payload.Payload, error)

// getMonitorParser constructs and returns an eventParserFunc. It is
// appropriate for the monitor API version passed in.
func getMonitorParser(conn net.Conn, version listener.Version) (parser eventParserFunc, err error) {
	switch version {
	case listener.Version1_2:
		var (
			pl  payload.Payload
			dec = gob.NewDecoder(conn)
		)
		// This implemenents the newer 1.2 API. Each listener maintains its own gob
		// session, and type information is only ever sent once.
		return func() (*payload.Payload, error) {
			if err := pl.DecodeBinary(dec); err != nil {
				return nil, err
			}
			return &pl, nil
		}, nil

	default:
		return nil, fmt.Errorf("unsupported version %s", version)
	}
}

func endpointsExist(endpoints format.Uint16Flags, existingEndpoints []*models.Endpoint) bool {
	endpointsFound := format.Uint16Flags{}
	for _, ep := range existingEndpoints {
		if endpoints.Has(uint16(ep.ID)) {
			endpointsFound = append(endpointsFound, uint16(ep.ID))
		}
	}

	if len(endpointsFound) < len(endpoints) {
		for _, endpoint := range endpoints {
			if !endpointsFound.Has(endpoint) {
				fmt.Fprintf(os.Stderr, "endpoint %d not found\n", endpoint)
			}
		}
	}

	return len(endpointsFound) > 0
}

func validateEndpointsFilters() {
	if !(len(printer.FromSource) > 0) ||
		!(len(printer.ToDst) > 0) ||
		!(len(printer.Related) > 0) {
		return
	}

	existingEndpoints, err := client.EndpointList()
	if err != nil {
		Fatalf("cannot get endpoint list: %s\n", err)
	}

	validFilter := false
	if len(printer.FromSource) > 0 {
		if endpointsExist(printer.FromSource, existingEndpoints) {
			validFilter = true
		}
	}
	if len(printer.ToDst) > 0 {
		if endpointsExist(printer.ToDst, existingEndpoints) {
			validFilter = true
		}
	}

	if len(printer.Related) > 0 {
		if endpointsExist(printer.Related, existingEndpoints) {
			validFilter = true
		}
	}

	// exit if all filters are not not found
	if !validFilter {
		os.Exit(1)
	}
}

func runMonitor(args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "Error: arguments not recognized")
		os.Exit(1)
	}

	validateEndpointsFilters()
	setVerbosity()
	setupSigHandler()
	if resp, err := client.Daemon.GetHealthz(nil); err == nil {
		if nm := resp.Payload.NodeMonitor; nm != nil {
			fmt.Fprintf(os.Stderr, "Listening for events on %d CPUs with %dx%d of shared memory\n",
				nm.Cpus, nm.Npages, nm.Pagesize)
		}
	}
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to quit\n")

	// On EOF, retry
	// On other errors, exit
	// always wait connTimeout when retrying
	for ; ; time.Sleep(connTimeout) {
		conn, version, err := openMonitorSock(vp.GetString("monitor-socket"))
		if err != nil {
			log.WithError(err).Error("Cannot open monitor socket")
			return
		}

		err = consumeMonitorEvents(conn, version)
		switch {
		case err == nil:
		// no-op

		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			log.WithError(err).Warn("connection closed")
			continue

		default:
			log.WithError(err).Fatal("decoding error")
		}
	}
}
