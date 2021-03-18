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
	"errors"

	recorderpb "github.com/cilium/cilium/api/v1/recorder"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	log logrus.FieldLogger
}

var _ recorderpb.RecorderServer = (*Service)(nil)

func (s *Service) Record(stream recorderpb.Recorder_RecordServer) error {
	var (
		sink        *recorderpb.FileSinkConfiguration
		isRecording bool
	)

	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		switch {
		case req.GetStart() != nil && !isRecording:
			sink = req.GetStart().GetFilesink()
			filter := req.GetStart().GetInclude()
			s.log.WithFields(logrus.Fields{
				"sink":   sink,
				"filter": filter,
			}).Info("start recording")

			isRecording = true
		case req.GetStop() != nil && isRecording:
			s.log.WithFields(logrus.Fields{
				"sink": sink,
			}).Info("stop recording")

			stream.Send(&recorderpb.RecordResponse{
				NodeName: nodeTypes.GetName(),
				Time:     timestamppb.Now(),
				ResponseType: &recorderpb.RecordResponse_Stopped{
					Stopped: &recorderpb.RecordingStoppedResponse{
						Stats: nil,
						Filesink: &recorderpb.FileSinkResult{
							FilePath: "",
						},
					},
				},
			})

			// exit this function to close the connection
			return nil
		default:
			return errors.New("received unsupported recorder request")
		}
	}
}
