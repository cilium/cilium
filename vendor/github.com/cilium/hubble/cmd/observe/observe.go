// Copyright 2019 Authors of Hubble
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

package observe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/gogo/protobuf/types"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/api/v1/observer"
	"github.com/cilium/hubble/pkg/api"
	hubprinter "github.com/cilium/hubble/pkg/printer"
	hubtime "github.com/cilium/hubble/pkg/time"
)

var (
	last               uint64
	sinceVar, untilVar string

	jsonOutput            bool
	compactOutput         bool
	dictOutput            bool
	output                string
	follow                bool
	ignoreStderr          bool
	enableIPTranslation   bool
	enablePortTranslation bool

	printer *hubprinter.Printer

	allTypes = []string{
		monitorAPI.MessageTypeNameL7,
		monitorAPI.MessageTypeNameDrop,
		monitorAPI.MessageTypeNameTrace,
		// Currently we don't parse the following three as they are deemed too
		// noisy:
		// monitorAPI.MessageTypeDebug,
		// monitorAPI.MessageTypeCapture,
		// monitorAPI.MessageTypeAgent,
	}

	serverURL        string
	serverTimeoutVar string
	serverTimeout    time.Duration

	numeric bool
)

func eventTypes() (l []string) {
	for t := range monitorAPI.MessageTypeNames {
		l = append(l, t)
	}
	return
}

// New observer command.
func New() *cobra.Command {
	return newObserveCmd(newObserveFilter())
}

func newObserveCmd(ofilter *observeFilter) *cobra.Command {
	observerCmd := &cobra.Command{
		Use:   "observe",
		Short: "Display BPF program events running in the local node",
		Long: `The hubble observer displays notifications and events emitted by the BPF
programs attached to endpoints and devices. This includes:
  * Dropped packet notifications
  * Captured packet traces
  * Debugging information`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := handleArgs(ofilter); err != nil {
				return err
			}

			if err := runObserve(serverURL, ofilter); err != nil {
				msg := err.Error()
				// extract custom error message from failed grpc call
				if s, ok := status.FromError(err); ok && s.Code() == codes.Unknown {
					msg = s.Message()
				}
				return errors.New(msg)
			}
			return nil
		},
	}
	observerCmd.Flags().StringVarP(&serverURL,
		"server", "", api.GetDefaultSocketPath(),
		"URL to connect to server")
	observerCmd.Flags().StringVar(&serverTimeoutVar,
		"timeout", "5s",
		"How long to wait before giving up on server dialing")
	observerCmd.Flags().VarP(filterVarP(
		"type", "t", ofilter, allTypes,
		fmt.Sprintf("Filter by event types TYPE[:SUBTYPE] (%v)", eventTypes())))

	observerCmd.Flags().Uint64Var(&last, "last", 0, "Get last N flows stored in the hubble")
	observerCmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow flows output")
	observerCmd.Flags().StringVar(&sinceVar, "since", "", "Filter flows since a specific date (relative or RFC3339)")
	observerCmd.Flags().StringVar(&untilVar, "until", "", "Filter flows until a specific date (relative or RFC3339)")

	observerCmd.Flags().Var(filterVar(
		"not", ofilter,
		"Reverses the next filter to be blacklist i.e. --not --from-ip 2.2.2.2"))
	observerCmd.Flags().Lookup("not").NoOptDefVal = "true"

	observerCmd.Flags().Var(filterVar(
		"from-fqdn", ofilter,
		"Show all flows originating at the given fully qualified domain name (e.g. \"*.cilium.io\")."))
	observerCmd.Flags().Var(filterVar(
		"fqdn", ofilter,
		"Show all flows related to the given fully qualified domain name (e.g. \"*.cilium.io\")."))
	observerCmd.Flags().Var(filterVar(
		"to-fqdn", ofilter,
		"Show all flows terminating at the given fully qualified domain name (e.g. \"*.cilium.io\")."))

	observerCmd.Flags().Var(filterVar(
		"from-ip", ofilter,
		"Show all flows originating at the given IP address."))
	observerCmd.Flags().Var(filterVar(
		"ip", ofilter,
		"Show all flows related to the given IP address."))
	observerCmd.Flags().Var(filterVar(
		"to-ip", ofilter,
		"Show all flows terminating at the given IP address."))

	observerCmd.Flags().Var(filterVar(
		"from-pod", ofilter,
		"Show all flows originating in the given pod name ([namespace/]<pod-name>). If namespace is not provided, 'default' is used"))
	observerCmd.Flags().Var(filterVar(
		"pod", ofilter,
		"Show all flows related to the given pod name ([namespace/]<pod-name>). If namespace is not provided, 'default' is used"))
	observerCmd.Flags().Var(filterVar(
		"to-pod", ofilter,
		"Show all flows terminating in the given pod name ([namespace/]<pod-name>). If namespace is not provided, 'default' is used"))

	observerCmd.Flags().Var(filterVar(
		"from-namespace", ofilter,
		"Show all flows originating in the given Kubernetes namespace."))
	observerCmd.Flags().VarP(filterVarP(
		"namespace", "n", ofilter, nil,
		"Show all flows related to the given Kubernetes namespace."))
	observerCmd.Flags().Var(filterVar(
		"to-namespace", ofilter,
		"Show all flows terminating in the given Kubernetes namespace."))

	observerCmd.Flags().Var(filterVar(
		"from-label", ofilter,
		"Show only flows originating in an endpoint with the given labels (e.g. \"key1=value1\", \"reserved:world\")"))
	observerCmd.Flags().VarP(filterVarP(
		"label", "l", ofilter, nil,
		"Show only flows related to an endpoint with the given labels (e.g. \"key1=value1\", \"reserved:world\")"))
	observerCmd.Flags().Var(filterVar(
		"to-label", ofilter,
		"Show only flows terminating in an endpoint with given labels (e.g. \"key1=value1\", \"reserved:world\")"))

	observerCmd.Flags().Var(filterVar(
		"from-service", ofilter,
		"Show all flows originating in the given service ([namespace/]<svc-name>). If namespace is not provided, 'default' is used"))
	observerCmd.Flags().Var(filterVar(
		"service", ofilter,
		"Show all flows related to the given service ([namespace/]<svc-name>). If namespace is not provided, 'default' is used"))
	observerCmd.Flags().Var(filterVar(
		"to-service", ofilter,
		"Show all flows terminating in the given service ([namespace/]<svc-name>). If namespace is not provided, 'default' is used"))

	observerCmd.Flags().Var(filterVar(
		"verdict", ofilter,
		fmt.Sprintf("Show only flows with this verdict [%v, %v]", pb.Verdict_FORWARDED, pb.Verdict_DROPPED)))

	observerCmd.Flags().Var(filterVar(
		"http-status", ofilter,
		"Show only flows which match this HTTP status code prefix (e.g. \"404\", \"5+\")"))

	observerCmd.Flags().Var(filterVar(
		"protocol", ofilter,
		"Show only flows which match the given L4/L7 flow protocol (e.g. \"udp\", \"http\")"))

	observerCmd.Flags().Var(filterVar(
		"from-port", ofilter,
		"Show only flows with the given source port (e.g. 8080)"))
	observerCmd.Flags().Var(filterVar(
		"port", ofilter,
		"Show only flows with given port in either source or destination (e.g. 8080)"))
	observerCmd.Flags().Var(filterVar(
		"to-port", ofilter,
		"Show only flows with the given destination port (e.g. 8080)"))

	observerCmd.Flags().Var(filterVar(
		"from-identity", ofilter,
		"Show all flows originating at an endpoint with the given security identity"))
	observerCmd.Flags().Var(filterVar(
		"identity", ofilter,
		"Show all flows related to an endpoint with the given security identity"))
	observerCmd.Flags().Var(filterVar(
		"to-identity", ofilter,
		"Show all flows terminating at an endpoint with the given security identity"))

	observerCmd.Flags().BoolVarP(
		&jsonOutput, "json", "j", false, "Deprecated. Use '--output json' instead.",
	)
	observerCmd.Flags().BoolVar(
		&compactOutput, "compact", false, "Deprecated. Use '--output compact' instead.",
	)
	observerCmd.Flags().BoolVar(
		&dictOutput, "dict", false, "Deprecated. Use '--output dict' instead.",
	)
	observerCmd.Flags().StringVarP(
		&output, "output", "o", "",
		"Specify the output format, one of:\n -compact:\tcompact output\n -dict:\teach flow is shown as KEY:VALUE pair\n -json:\tJSON encoding\n -table:\ttab-aligned columns",
	)
	observerCmd.Flags().BoolVarP(
		&ignoreStderr, "silent-errors", "s", false, "Silently ignores errors and warnings")

	observerCmd.Flags().BoolVar(
		&numeric,
		"numeric",
		false,
		"Display all information in numeric form",
	)

	observerCmd.Flags().BoolVar(
		&enablePortTranslation,
		"port-translation",
		true,
		"Translate port numbers to names",
	)

	observerCmd.Flags().BoolVar(
		&enableIPTranslation,
		"ip-translation",
		true,
		"Translate IP addresses to logical names such as pod name, FQDN, ...",
	)

	customObserverHelp(observerCmd)

	return observerCmd
}

func handleArgs(ofilter *observeFilter) (err error) {
	if ofilter.blacklisting {
		return errors.New("trailing --not found in the arguments")
	}

	serverTimeout, err = time.ParseDuration(serverTimeoutVar)
	if err != nil {
		return fmt.Errorf("failed to parse server-timeout duration: %v", err)
	}

	// initialize the printer with any options that were passed in
	var opts []hubprinter.Option

	if output == "" { // support deprecated output flags if provided
		if jsonOutput {
			output = "json"
		} else if dictOutput {
			output = "dict"
		} else if compactOutput {
			output = "compact"
		}
	}

	switch output {
	case "compact":
		opts = append(opts, hubprinter.Compact())
	case "dict":
		opts = append(opts, hubprinter.Dict())
	case "json", "JSON":
		opts = append(opts, hubprinter.JSON())
	case "tab", "table":
		if follow {
			return fmt.Errorf("table output format is not compatible with follow mode")
		}
		opts = append(opts, hubprinter.Tab())
	case "":
		// no format specified, choose most appropriate format based on
		// user provided flags
		if follow {
			opts = append(opts, hubprinter.Compact())
		} else {
			opts = append(opts, hubprinter.Tab())
		}
	default:
		return fmt.Errorf("invalid output format: %s", output)
	}
	if ignoreStderr {
		opts = append(opts, hubprinter.IgnoreStderr())
	}
	if numeric {
		enableIPTranslation = false
		enablePortTranslation = false
	}
	if enableIPTranslation {
		opts = append(opts, hubprinter.WithIPTranslation())
	}
	if enablePortTranslation {
		opts = append(opts, hubprinter.WithPortTranslation())
	}
	printer = hubprinter.New(opts...)
	return nil
}

func runObserve(serverURL string, ofilter *observeFilter) error {
	ctx, cancel := context.WithTimeout(context.Background(), serverTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, serverURL, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("failed to dial grpc: %v", err)
	}
	defer conn.Close()

	// convert sinceVar into a param for GetFlows
	var since, until *types.Timestamp
	if sinceVar != "" {
		st, err := hubtime.FromString(sinceVar)
		if err != nil {
			return fmt.Errorf("failed to parse the since time: %v", err)
		}

		since, err = types.TimestampProto(st)
		if err != nil {
			return fmt.Errorf("failed to convert `since` timestamp to proto: %v", err)
		}
		// Set the until field if both --since and --until options are specified and --follow
		// is not specified. If --since is specified but --until is not, the server sets the
		// --until option to the current timestamp.
		if untilVar != "" && !follow {
			ut, err := hubtime.FromString(untilVar)
			if err != nil {
				return fmt.Errorf("failed to parse the until time: %v", err)
			}
			until, err = types.TimestampProto(ut)
			if err != nil {
				return fmt.Errorf("failed to convert `until` timestamp to proto: %v", err)
			}
		}
	}

	// no specific parameters were provided, just a vanilla `hubble observe`
	if last == 0 && since == nil && until == nil {
		// assume --last 20
		last = 20
	}

	var (
		wl []*pb.FlowFilter
		bl []*pb.FlowFilter
	)
	if ofilter.whitelist != nil {
		wl = ofilter.whitelist.flowFilters()
	}
	if ofilter.blacklist != nil {
		bl = ofilter.blacklist.flowFilters()
	}

	client := observer.NewObserverClient(conn)
	req := &observer.GetFlowsRequest{
		Number:    last,
		Follow:    follow,
		Whitelist: wl,
		Blacklist: bl,
		Since:     since,
		Until:     until,
	}

	return getFlows(client, req)
}

func getFlows(client observer.ObserverClient, req *observer.GetFlowsRequest) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := client.GetFlows(ctx, req)
	if err != nil {
		return err
	}

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
		select {
		case <-sigs:
		case <-ctx.Done():
			signal.Stop(sigs)
		}
		cancel()
	}()

	defer printer.Close()

	for {
		getFlowResponse, err := b.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return nil
		case nil:
		default:
			if status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		flow := getFlowResponse.GetFlow()
		if flow == nil {
			continue
		}

		err = printer.WriteProtoFlow(flow)
		if err != nil {
			return err
		}
	}
}
