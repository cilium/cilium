// Copyright 2021 Authors of Cilium
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

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
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

type recording struct {
	ruleID   uint16
	filePath string
	handle   *sink.Handle
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

func (s *Service) Record(stream recorderpb.Recorder_RecordServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	startRecording := req.GetStart()
	if startRecording == nil {
		return fmt.Errorf("received invalid request %q, expected start request", req)
	}

	rec, err := s.startRecording(ctx, startRecording)
	if err != nil {
		return err
	}

	go s.watchRecording(ctx, rec.handle, stream)

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	if req.GetStop() == nil {
		return fmt.Errorf("received invalid request %q, expected stop request", req)
	}

	resp, err := s.stopRecording(ctx, rec)
	if err != nil {
		return err
	}

	err = stream.Send(&recorderpb.RecordResponse{
		NodeName: nodeTypes.GetName(),
		Time:     timestamppb.Now(),
		ResponseType: &recorderpb.RecordResponse_Stopped{
			Stopped: resp,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

const fileExistsRetries = 100

func createPcapFile(basedir, prefix string) (f *os.File, filePath string, err error) {
	try := 0
	for {
		startTime := time.Now().Unix()
		random := rand.Uint32()
		nodeName := nodeTypes.GetName()
		name := fmt.Sprintf("%s_%d_%d_%s.pcap", prefix, startTime, random, nodeName)
		filePath = path.Join(basedir, name)
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

func (s *Service) startRecording(ctx context.Context, req *recorderpb.StartRecording) (*recording, error) {
	capLen := req.GetMaxCaptureLength()
	prefix := req.GetFilesink().GetFilePrefix()
	if prefix == "" {
		prefix = defaultFileSinkPrefix
	}

	if !fileSinkPrefixRegex.MatchString(prefix) {
		return nil, fmt.Errorf("invalid file sink prefix: %q", prefix)
	}

	filters, err := parseFilters(req.GetInclude())
	if err != nil {
		return nil, err
	}

	leaseID := s.ruleIDs.LeaseAvailableID()
	ruleID := uint16(leaseID)
	if leaseID == idpool.NoID {
		return nil, errors.New("unable to allocate capture rule id")
	}

	f, filePath, err := createPcapFile(s.opts.StoragePath, prefix)
	if err != nil {
		return nil, err
	}

	r := &recording{ruleID: ruleID, filePath: filePath}
	defer func() {
		// clean up the recording if any of the subsequent steps fails
		if err != nil {
			_, _ = s.recorder.DeleteRecorder(recorder.ID(r.ruleID))
			// if the sink has not been registered, UnregisterSink will just
			// return an error which we can ignore here
			_, _ = s.dispatch.UnregisterSink(ctx, r.ruleID)
			// remove the created pcap file
			_ = f.Close()
			_ = os.Remove(r.filePath)
			// release will also invalidate the lease
			_ = s.ruleIDs.Release(idpool.ID(r.ruleID))
		}
	}()

	log.WithFields(logrus.Fields{
		"ruleID":   r.ruleID,
		"filePath": r.filePath,
	}).Debug("starting new recording")

	pcapWriter := pcap.NewWriter(f)
	pcapHeader := pcap.Header{
		SnapshotLength: capLen,
		Datalink:       pcap.Ethernet,
	}

	r.handle, err = s.dispatch.RegisterSink(ctx, ruleID, pcapWriter, pcapHeader)
	if err != nil {
		return nil, err
	}

	recInfo := &recorder.RecInfo{
		ID:      recorder.ID(ruleID),
		CapLen:  uint16(capLen),
		Filters: filters,
	}
	_, err = s.recorder.UpsertRecorder(recInfo)
	if err != nil {
		return nil, err
	}

	s.ruleIDs.Use(leaseID)

	return r, nil
}

func (s *Service) stopRecording(ctx context.Context, r *recording) (*recorderpb.RecordingStoppedResponse, error) {
	log.WithFields(logrus.Fields{
		"ruleID":   r.ruleID,
		"filePath": r.filePath,
	}).Debug("stopping recording")

	_, err := s.recorder.DeleteRecorder(recorder.ID(r.ruleID))
	if err != nil {
		return nil, err
	}

	stats, err := s.dispatch.UnregisterSink(ctx, r.ruleID)
	if err != nil {
		return nil, err
	}

	s.ruleIDs.Release(idpool.ID(r.ruleID))

	return &recorderpb.RecordingStoppedResponse{
		Stats: &recorderpb.RecordingStatistics{
			BytesCaptured:   stats.BytesWritten,
			PacketsCaptured: stats.PacketsWritten,
			BytesLost:       stats.BytesLost,
			PacketsLost:     stats.PacketsLost,
		},
		Filesink: &recorderpb.FileSinkResult{FilePath: r.filePath},
	}, nil
}

func (s *Service) watchRecording(ctx context.Context, h *sink.Handle, stream recorderpb.Recorder_RecordServer) {
	for {
		stats := h.Stats()
		err := stream.Send(&recorderpb.RecordResponse{
			NodeName: nodeTypes.GetName(),
			Time:     timestamppb.Now(),
			ResponseType: &recorderpb.RecordResponse_Running{
				Running: &recorderpb.RecordingRunningResponse{
					Stats: &recorderpb.RecordingStatistics{
						BytesCaptured:   stats.BytesWritten,
						PacketsCaptured: stats.PacketsWritten,
						BytesLost:       stats.BytesLost,
						PacketsLost:     stats.PacketsLost,
					}},
			},
		})
		if err != nil {
			// errors are expected if the client disconnects early, therefore
			// we do not log this as an error or warning
			log.WithError(err).Debug("failed to send recording update")
			return
		}

		select {
		case _, ok := <-h.C:
			if !ok {
				// sink closed
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
