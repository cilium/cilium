// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	"github.com/cilium/cilium/hubble/pkg/logger"
	hubtime "github.com/cilium/cilium/hubble/pkg/time"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func newAgentEventsCommand(vp *viper.Viper) *cobra.Command {
	agentEventsCmd := &cobra.Command{
		Use:   "agent-events",
		Short: "Observe Cilium agent events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			debug := vp.GetBool(config.KeyDebug)
			if err := handleEventsArgs(cmd.OutOrStdout(), debug); err != nil {
				return err
			}
			req, err := getAgentEventsRequest()
			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, os.Kill)
			defer cancel()

			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			client := observerpb.NewObserverClient(hubbleConn)
			logger.Logger.Debug("Sending GetAgentEvents request", logfields.Request, req)
			if err := getAgentEvents(ctx, client, req); err != nil {
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

	flagSets := []*pflag.FlagSet{selectorFlags, formattingFlags, config.ServerFlags, otherFlags}
	for _, fs := range flagSets {
		agentEventsCmd.Flags().AddFlagSet(fs)
	}
	template.RegisterFlagSets(agentEventsCmd, flagSets...)
	return agentEventsCmd
}

func getAgentEventsRequest() (*observerpb.GetAgentEventsRequest, error) {
	// convert selectorOpts.since into a param for GetAgentEvents
	var since, until *timestamppb.Timestamp
	if selectorOpts.since != "" {
		st, err := hubtime.FromString(selectorOpts.since)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the since time: %w", err)
		}

		since = timestamppb.New(st)
		if err := since.CheckValid(); err != nil {
			return nil, fmt.Errorf("failed to convert `since` timestamp to proto: %w", err)
		}
	}
	// Set the until field if --until option is specified and --follow
	// is not specified. If --since is specified but --until is not, the server sets the
	// --until option to the current timestamp.
	if selectorOpts.until != "" && !selectorOpts.follow {
		ut, err := hubtime.FromString(selectorOpts.until)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the until time: %w", err)
		}
		until = timestamppb.New(ut)
		if err := until.CheckValid(); err != nil {
			return nil, fmt.Errorf("failed to convert `until` timestamp to proto: %w", err)
		}
	}

	if since == nil && until == nil {
		switch {
		case selectorOpts.all:
			// all is an alias for last=uint64_max
			selectorOpts.last = math.MaxUint64
		case selectorOpts.last == 0:
			// no specific parameters were provided, just a vanilla `hubble events agent`
			selectorOpts.last = defaults.EventsPrintCount
		}
	}

	return &observerpb.GetAgentEventsRequest{
		Number: selectorOpts.last,
		Follow: selectorOpts.follow,
		Since:  since,
		Until:  until,
	}, nil
}

func getAgentEvents(ctx context.Context, client observerpb.ObserverClient, req *observerpb.GetAgentEventsRequest) error {
	b, err := client.GetAgentEvents(ctx, req)
	if err != nil {
		return err
	}
	defer printer.Close()

	for {
		resp, err := b.Recv()
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, context.Canceled):
			return nil
		case err == nil:
		default:
			if status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		if err = printer.WriteProtoAgentEvent(resp); err != nil {
			return err
		}
	}
}
