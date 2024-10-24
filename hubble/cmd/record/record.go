// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package record

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	recorderpb "github.com/cilium/cilium/api/v1/recorder"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/pkg/time"
)

const (
	filterSep = " "
)

var (
	fileSinkPrefix   string
	maxCaptureLength uint32

	packetLimit, bytesLimit uint64
	timeLimit               time.Duration
)

// New creates a new record subcommand
func New(vp *viper.Viper) *cobra.Command {
	recordCmd := &cobra.Command{
		Use:   "record [flags] filter1 filter2 ... filterN",
		Short: "Capture and record network packets",
		Long:  "Capture and record network packets into a pcap file stored on the Hubble server",
		Example: `
Record all TCP traffic from 192.168.1.0/24 (any source port) to 10.0.0.0/16 port 80:

  hubble record "192.168.1.0/24 0 10.0.0.0/16 80 TCP"

Multiple filters may be specified, in which case any matching packet will be recorded.
The filter syntax is "srcPrefix srcPort dstPrefix dstPort proto". Currently supported
protocols are TCP, UDP, SCTP, and ANY.`,
		Hidden: true, // this command is experimental
		RunE: func(cmd *cobra.Command, args []string) error {
			filters, err := parseFilters(args)
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

			return runRecord(ctx, hubbleConn, filters)
		},
	}

	recorderFlags := pflag.NewFlagSet("recorder", pflag.ContinueOnError)
	recorderFlags.StringVar(&fileSinkPrefix, "file-prefix", "hubble", "File prefix of the resulting pcap file")
	recorderFlags.Uint32Var(&maxCaptureLength, "max-capture-len", 0, "Sets the maximum capture length (zero for full capture)")

	recorderFlags.Uint64Var(&packetLimit, "packet-limit", 0, "Sets a limit on how many packets to capture on each node")
	recorderFlags.Uint64Var(&bytesLimit, "bytes-limit", 0, "Sets a limit on how many bytes to capture on each node")
	recorderFlags.DurationVar(&timeLimit, "time-limit", 0, "Sets a limit on how long to capture on each node")

	recordCmd.Flags().AddFlagSet(recorderFlags)
	template.RegisterFlagSets(recordCmd, config.ServerFlags, recorderFlags)

	return recordCmd
}

func parseProto(proto string) (recorderpb.Protocol, error) {
	switch strings.ToUpper(proto) {
	case "TCP":
		return recorderpb.Protocol_PROTOCOL_TCP, nil
	case "UDP":
		return recorderpb.Protocol_PROTOCOL_UDP, nil
	case "SCTP":
		return recorderpb.Protocol_PROTOCOL_SCTP, nil
	case "ANY":
		return recorderpb.Protocol_PROTOCOL_ANY, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func parseFilters(filters []string) ([]*recorderpb.Filter, error) {
	if len(filters) == 0 {
		return nil, errors.New("need to specify at least one filter")
	}

	result := make([]*recorderpb.Filter, 0, len(filters))
	for _, filter := range filters {
		f := strings.SplitN(filter, filterSep, 5)
		if len(f) != 5 {
			return nil, fmt.Errorf("invalid 5-tuple filter: %q", f)
		}

		srcPrefix := f[0]
		srcPort, err := strconv.ParseUint(f[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid source port: %s", f[1])
		}
		dstPrefix := f[2]
		dstPort, err := strconv.ParseUint(f[3], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid destination port: %s", f[3])
		}
		proto, err := parseProto(f[4])
		if err != nil {
			return nil, err
		}

		result = append(result, &recorderpb.Filter{
			SourceCidr:      srcPrefix,
			SourcePort:      uint32(srcPort),
			DestinationCidr: dstPrefix,
			DestinationPort: uint32(dstPort),
			Protocol:        proto,
		})
	}

	return result, nil
}

func fmtTime(resp *recorderpb.RecordResponse) string {
	return resp.GetTime().AsTime().Format(time.RFC3339)
}

func fmtStats(stats *recorderpb.RecordingStatistics) string {
	output := fmt.Sprintf("%d packets (%d bytes) written",
		stats.GetPacketsCaptured(), stats.GetBytesCaptured())
	if stats.GetPacketsLost() > 0 || stats.GetBytesLost() > 0 {
		output = fmt.Sprintf("%s and %d packets (%d bytes) lost",
			output, stats.GetPacketsLost(), stats.GetBytesLost())
	}
	return output
}

func runRecord(ctx context.Context, conn *grpc.ClientConn, filters []*recorderpb.Filter) error {
	stdoutIsTTY := isTTY(os.Stdout)

	recorder, err := recorderpb.NewRecorderClient(conn).Record(ctx)
	if err != nil {
		return err
	}

	err = recorder.Send(&recorderpb.RecordRequest{
		RequestType: &recorderpb.RecordRequest_Start{
			Start: &recorderpb.StartRecording{
				Filesink: &recorderpb.FileSinkConfiguration{
					FilePrefix: fileSinkPrefix,
				},
				Include:          filters,
				MaxCaptureLength: maxCaptureLength,
				StopCondition: &recorderpb.StopCondition{
					BytesCapturedCount:   bytesLimit,
					PacketsCapturedCount: packetLimit,
					TimeElapsed:          durationpb.New(timeLimit),
				},
			},
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Started recording. Press CTRL+C to stop.\n")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Fprintf(os.Stderr, "Stopping recording...\n")
		err := recorder.Send(&recorderpb.RecordRequest{
			RequestType: &recorderpb.RecordRequest_Stop{
				Stop: &recorderpb.StopRecording{},
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to send stop recording message: %s\n", err)
		}
	}()

	statusPrinted := false
	for {
		stats, err := recorder.Recv()
		switch {
		case err != nil:
			return err
		case stats.GetRunning() != nil:
			if stdoutIsTTY && statusPrinted {
				clearLastLine(os.Stdout)
			}
			fmt.Printf("%s Status: %s\n", fmtTime(stats), fmtStats(stats.GetRunning().GetStats()))
			statusPrinted = true
		case stats.GetStopped() != nil:
			filepath := stats.GetStopped().GetFilesink().GetFilePath()
			fmt.Printf("%s Result: %s\n", fmtTime(stats), fmtStats(stats.GetStopped().GetStats()))
			fmt.Printf("%s Output: %s\n", fmtTime(stats), filepath)
			return nil
		}
	}
}
