// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/cilium/monitor/listener"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/format"
	"github.com/cilium/cilium/pkg/monitor/payload"

	"github.com/spf13/cobra"
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
  * Debugging information`,
		Run: func(cmd *cobra.Command, args []string) {
			runMonitor(args)
		},
	}
	printer = format.NewMonitorFormatter(format.INFO)
)

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().BoolVar(&printer.Hex, "hex", false, "Do not dissect, print payload in HEX")
	monitorCmd.Flags().VarP(&printer.EventTypes, "type", "t", fmt.Sprintf("Filter by event types %v", monitor.GetAllTypes()))
	monitorCmd.Flags().Var(&printer.FromSource, "from", "Filter by source endpoint id")
	monitorCmd.Flags().Var(&printer.ToDst, "to", "Filter by destination endpoint id")
	monitorCmd.Flags().Var(&printer.Related, "related-to", "Filter by either source or destination endpoint id")
	monitorCmd.Flags().BoolVarP(&printer.Verbose, "verbose", "v", false, "Enable verbose output")
	monitorCmd.Flags().BoolVarP(&printer.JSONOutput, "json", "j", false, "Enable json output. Shadows -v flag")
}

func setVerbosity() {
	if printer.JSONOutput {
		printer.Verbosity = format.JSON
	} else if printer.Verbose {
		printer.Verbosity = format.DEBUG
	} else {
		printer.Verbosity = format.INFO
	}
}

func setupSigHandler() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for range signalChan {
			fmt.Printf("\nReceived an interrupt, disconnecting from monitor...\n\n")
			os.Exit(0)
		}
	}()
}

// openMonitorSock attempts to open a version specific monitor socket It
// returns a connection, with a version, or an error.
func openMonitorSock() (conn net.Conn, version listener.Version, err error) {
	errors := make([]string, 0)

	// try the 1.2 socket
	conn, err = net.Dial("unix", defaults.MonitorSockPath1_2)
	if err == nil {
		return conn, listener.Version1_2, nil
	}
	errors = append(errors, defaults.MonitorSockPath1_2+": "+err.Error())

	// try the 1.1 socket
	conn, err = net.Dial("unix", defaults.MonitorSockPath1_0)
	if err == nil {
		return conn, listener.Version1_0, nil
	}
	errors = append(errors, defaults.MonitorSockPath1_0+": "+err.Error())

	return nil, listener.VersionUnsupported, fmt.Errorf("Cannot find or open a supported node-monitor socket. %s", strings.Join(errors, ","))
}

// consumeMonitorEvents handles and prints events on a monitor connection. It
// calls getMonitorParsed to construct a monitor-version appropraite parser.
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
	case listener.Version1_0:
		var (
			meta payload.Meta
			pl   payload.Payload
		)
		// This implements the older API. Always encode a Meta and Payload object,
		// both with full gob type information
		return func() (*payload.Payload, error) {
			if err := payload.ReadMetaPayload(conn, &meta, &pl); err != nil {
				return nil, err
			}
			return &pl, nil
		}, nil

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

func runMonitor(args []string) {
	if len(args) > 0 {
		fmt.Println("Error: arguments not recognized")
		os.Exit(1)
	}

	setVerbosity()
	setupSigHandler()
	if resp, err := client.Daemon.GetHealthz(nil); err == nil {
		if nm := resp.Payload.NodeMonitor; nm != nil {
			fmt.Printf("Listening for events on %d CPUs with %dx%d of shared memory\n",
				nm.Cpus, nm.Npages, nm.Pagesize)
		}
	}
	fmt.Printf("Press Ctrl-C to quit\n")

	// On EOF, retry
	// On other errors, exit
	// always wait connTimeout when retrying
	for ; ; time.Sleep(connTimeout) {
		conn, version, err := openMonitorSock()
		if err != nil {
			log.WithError(err).Error("Cannot open monitor socket")
			return
		}

		err = consumeMonitorEvents(conn, version)
		switch {
		case err == nil:
		// no-op

		case err == io.EOF, err == io.ErrUnexpectedEOF:
			log.WithError(err).Warn("connection closed")
			continue

		default:
			log.WithError(err).Fatal("decoding error")
		}
	}
}
