// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"regexp"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	recorderpb "github.com/cilium/cilium/api/v1/recorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/hubble/recorder/pcap"
	"github.com/cilium/cilium/pkg/hubble/recorder/recorderoption"
	"github.com/cilium/cilium/pkg/hubble/recorder/sink"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/recorder"
	"github.com/cilium/cilium/pkg/u8proto"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-recorder")

var _ recorderpb.RecorderServer = (*Service)(nil)

const (
	minRuleID = 1
	maxRuleID = 65534

	defaultFileSinkPrefix = "hubble"
)

type Service struct {
	recorder *recorder.Recorder
	dispatch *sink.Dispatch
	ruleIDs  idpool.IDPool
	opts     recorderoption.Options
}

func NewService(r *recorder.Recorder, d *sink.Dispatch, options ...recorderoption.Option) (*Service, error) {
	opts := recorderoption.Default
	for _, o := range options {
		if err := o(&opts); err != nil {
			return nil, err
		}
	}

	if len(opts.StoragePath) == 0 {
		return nil, errors.New("storage path must not be empty")
	}

	if err := os.MkdirAll(opts.StoragePath, 0600); err != nil {
		return nil, fmt.Errorf("failed to create storage path directory: %w", err)
	}

	return &Service{
		recorder: r,
		dispatch: d,
		ruleIDs:  idpool.NewIDPool(minRuleID, maxRuleID),
		opts:     opts,
	}, nil
}

func recordingStoppedResponse(stats sink.Statistics, filePath string) *recorderpb.RecordResponse {
	return &recorderpb.RecordResponse{
		NodeName: nodeTypes.GetAbsoluteNodeName(),
		Time:     timestamppb.Now(),
		ResponseType: &recorderpb.RecordResponse_Stopped{
			Stopped: &recorderpb.RecordingStoppedResponse{
				Stats: &recorderpb.RecordingStatistics{
					BytesCaptured:   stats.BytesWritten,
					PacketsCaptured: stats.PacketsWritten,
					BytesLost:       stats.BytesLost,
					PacketsLost:     stats.PacketsLost,
				},
				Filesink: &recorderpb.FileSinkResult{
					FilePath: filePath,
				},
			},
		},
	}
}

func recordingRunningResponse(stats sink.Statistics) *recorderpb.RecordResponse {
	return &recorderpb.RecordResponse{
		NodeName: nodeTypes.GetAbsoluteNodeName(),
		Time:     timestamppb.Now(),
		ResponseType: &recorderpb.RecordResponse_Running{
			Running: &recorderpb.RecordingRunningResponse{
				Stats: &recorderpb.RecordingStatistics{
					BytesCaptured:   stats.BytesWritten,
					PacketsCaptured: stats.PacketsWritten,
					BytesLost:       stats.BytesLost,
					PacketsLost:     stats.PacketsLost,
				},
			},
		},
	}
}

func (s *Service) Record(stream recorderpb.Recorder_RecordServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// Spawn a goroutine that forwards any received messages in order to be
	// able to use select on it
	reqCh := make(chan *recorderpb.RecordRequest)
	errCh := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				errCh <- fmt.Errorf("failed to receive from recorder client: %w", err)
				return
			}

			select {
			case reqCh <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	var (
		recording *sink.Handle
		filePath  string
		err       error
	)

	// Wait for the initial StartRecording message
	select {
	case req := <-reqCh:
		startRecording := req.GetStart()
		if startRecording == nil {
			return fmt.Errorf("received invalid request %q, expected start request", req)
		}

		// The startRecording helper spawns a clean up goroutine to remove all
		// state associated with this recording when the context ctx is cancelled.
		recording, filePath, err = s.startRecording(ctx, startRecording)
		if err != nil {
			return err
		}
	case err = <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}

	// Send back a confirmation that the recording has started
	err = stream.Send(recordingRunningResponse(recording.Stats()))
	if err != nil {
		return fmt.Errorf("failed to confirmation response: %w", err)
	}

	for {
		select {
		// This case happens when the client has sent us a new request.
		// We expect a start request if recording is nil, and a stop request
		// otherwise.
		case req := <-reqCh:
			if req.GetStop() != nil {
				recording.Stop()
			} else {
				return fmt.Errorf("received invalid request %q, expected stop request", req)
			}
		// This case is hit whenever the recording has updated the statistics (i.e.
		// packets have been captured). We fetch the latest statistics and forward
		// them to the client
		case <-recording.StatsUpdated:
			err = stream.Send(recordingRunningResponse(recording.Stats()))
			if err != nil {
				return fmt.Errorf("failed to send recording running response: %w", err)
			}
		// This case happens when the recording has stopped (i.e. due to the above
		// explicit shutdown or because an error has occurred). If no error has
		// occurred, we assemble the final RecordingStoppedResponse and exit.
		// If an error occurred, we propagate it by returning it from this stub.
		case <-recording.Done:
			err = recording.Err()
			if err != nil {
				return fmt.Errorf("recorder recording error: %w", err)
			}

			err = stream.Send(recordingStoppedResponse(recording.Stats(), filePath))
			if err != nil {
				return fmt.Errorf("failed to send recording stopped response: %w", err)
			}

			return nil
		// The following two cases happen when the client stream is either
		// closed or cancelled. Simply return an error such that it is logged,
		// and exit.
		case err = <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

const fileExistsRetries = 100

var allowedFileChars = regexp.MustCompile("[^a-zA-Z0-9_.-]")

func createPcapFile(basedir, prefix string) (f *os.File, filePath string, err error) {
	try := 0
	for {
		startTime := time.Now().Unix()
		random := rand.Uint32()
		nodeName := nodeTypes.GetAbsoluteNodeName()
		name := fmt.Sprintf("%s_%d_%d_%s.pcap", prefix, startTime, random, nodeName)
		sanitizedName := allowedFileChars.ReplaceAllLiteralString(name, "_")
		filePath = path.Join(basedir, sanitizedName)
		f, err = os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if os.IsExist(err) {
				if try++; try < fileExistsRetries {
					continue
				}
			}
			return f, "", fmt.Errorf("failed to create pcap file %q: %w", filePath, err)
		}

		return f, filePath, nil
	}
}

func parseFilters(include []*recorderpb.Filter) ([]recorder.RecorderTuple, error) {
	if len(include) == 0 {
		return nil, errors.New("need to specify at least one include filter")
	}

	filters := []recorder.RecorderTuple{}
	for _, f := range include {
		srcIP, srcPrefix, err := net.ParseCIDR(f.GetSourceCidr())
		if err != nil {
			return nil, fmt.Errorf("failed to parse source cidr %q: %w", f.GetSourceCidr(), err)
		}

		dstIP, dstPrefix, err := net.ParseCIDR(f.GetDestinationCidr())
		if err != nil {
			return nil, fmt.Errorf("failed to parse source cidr %q: %w", f.GetDestinationCidr(), err)
		}

		if (srcIP.To4() == nil) != (dstIP.To4() == nil) {
			return nil, fmt.Errorf("source (%s) and destination cidr (%s) must be same protocol version",
				f.GetSourceCidr(), f.GetDestinationCidr())
		}

		const maxPort = 65535
		if f.GetSourcePort() > maxPort {
			return nil, fmt.Errorf("source port %d out of range", f.GetSourcePort())
		}

		if f.GetDestinationPort() > maxPort {
			return nil, fmt.Errorf("destination port %d out of range", f.GetDestinationPort())
		}

		filters = append(filters, recorder.RecorderTuple{
			SrcPrefix: *cidr.NewCIDR(srcPrefix),
			SrcPort:   uint16(f.GetSourcePort()),
			DstPrefix: *cidr.NewCIDR(dstPrefix),
			DstPort:   uint16(f.GetDestinationPort()),
			Proto:     u8proto.U8proto(f.GetProtocol()),
		})
	}

	return filters, nil
}

var fileSinkPrefixRegex = regexp.MustCompile("^[a-z][a-z0-9]{0,19}$")

// startRecording starts a new recording. It will clean up any state
// associated with the recording if ctx is cancelled or handle.Stop is called.
func (s *Service) startRecording(
	ctx context.Context,
	req *recorderpb.StartRecording,
) (handle *sink.Handle, filePath string, err error) {
	capLen := req.GetMaxCaptureLength()
	prefix := req.GetFilesink().GetFilePrefix()
	if prefix == "" {
		prefix = defaultFileSinkPrefix
	}

	if !fileSinkPrefixRegex.MatchString(prefix) {
		return nil, "", fmt.Errorf("invalid file sink prefix: %q", prefix)
	}

	filters, err := parseFilters(req.GetInclude())
	if err != nil {
		return nil, "", err
	}

	leaseID := s.ruleIDs.LeaseAvailableID()
	ruleID := uint16(leaseID)
	if leaseID == idpool.NoID {
		return nil, "", errors.New("unable to allocate capture rule id")
	}

	var f *os.File
	f, filePath, err = createPcapFile(s.opts.StoragePath, prefix)
	if err != nil {
		return nil, "", err
	}

	defer func() {
		// clean up the recording if any of the subsequent steps fails
		if err != nil {
			_, _ = s.recorder.DeleteRecorder(recorder.ID(ruleID))
			// remove the created pcap file
			_ = f.Close()
			_ = os.Remove(filePath)
			// release will also invalidate the lease
			_ = s.ruleIDs.Release(idpool.ID(ruleID))
		}
	}()

	scopedLog := log.WithFields(logrus.Fields{
		"ruleID":   ruleID,
		"filePath": filePath,
	})
	scopedLog.Debug("starting new recording")

	stop := req.GetStopCondition()
	config := sink.PcapSink{
		RuleID: ruleID,
		Header: pcap.Header{
			SnapshotLength: capLen,
			Datalink:       pcap.Ethernet,
		},
		Writer: pcap.NewWriter(f),
		StopCondition: sink.StopConditions{
			PacketsCaptured: stop.GetPacketsCapturedCount(),
			BytesCaptured:   stop.GetBytesCapturedCount(),
			DurationElapsed: stop.GetTimeElapsed().AsDuration(),
		},
	}

	// Upserting a new recorder can take up to a few seconds due to datapath
	// regeneration. To avoid having the stop condition timer on the sink
	// already running while the recorder is still being upserted, we install
	// the recorder before the sink. This is safe, as sink.Dispatch silently
	// ignores recordings for unknown sinks.
	recInfo := &recorder.RecInfo{
		ID:      recorder.ID(ruleID),
		CapLen:  uint16(capLen),
		Filters: filters,
	}
	_, err = s.recorder.UpsertRecorder(recInfo)
	if err != nil {
		return nil, "", err
	}

	handle, err = s.dispatch.StartSink(ctx, config)
	if err != nil {
		return nil, "", err
	}

	// Ensure to delete the above recorder when the sink has stopped
	go func() {
		<-handle.Done
		scopedLog.Debug("stopping recording")
		_, err := s.recorder.DeleteRecorder(recorder.ID(ruleID))
		if err != nil {
			scopedLog.WithError(err).Warning("failed to delete recorder")
		}
		s.ruleIDs.Release(idpool.ID(ruleID))
	}()

	s.ruleIDs.Use(leaseID)

	return handle, filePath, nil
}
