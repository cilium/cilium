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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	recorderpb "github.com/cilium/cilium/api/v1/recorder"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"

	"google.golang.org/grpc"
)

func newConn(ctx context.Context) (*grpc.ClientConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return grpc.DialContext(dialCtx, defaults.HubbleTarget)
}

func buildStartRequest(fileprefix string, filter *recorderpb.Filter) *recorderpb.RecordRequest {
	return &recorderpb.RecordRequest{
		RequestType: &recorderpb.RecordRequest_Start{
			Start: &recorderpb.StartRecording{
				Filesink: &recorderpb.FileSinkConfiguration{
					FilePrefix: fileprefix,
				},
				Include: []*recorderpb.Filter{filter},
			},
		},
	}
}

func buildStopRequest() *recorderpb.RecordRequest {
	return &recorderpb.RecordRequest{
		RequestType: &recorderpb.RecordRequest_Stop{
			Stop: &recorderpb.StopRecording{},
		},
	}
}

func doRecording() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := newConn(ctx)
	if err != nil {
		return err
	}

	recorder, err := recorderpb.NewRecorderClient(conn).Record(ctx)
	if err != nil {
		return err
	}

	// start recording
	recorder.Send(buildStartRequest("test", &recorderpb.Filter{
		SourceCidr:      "1.1.0.0/16",
		DestinationCidr: "0.0.0.0/0",
		DestinationPort: 80,
		Protocol:        recorderpb.Protocol_PROTOCOL_TCP,
	}))

	// stop the recording on CTRL+C
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		recorder.Send(buildStopRequest())
	}()

	for {
		// Waits for status messages from the server
		stats, err := recorder.Recv()
		switch {
		case err != nil:
			return err
		case stats.GetRunning() != nil:
			// This will be received in regular intervals after sending the
			// `StartRecording` msg
			fmt.Println("Recording status: ", stats)
		case stats.GetStopped() != nil:
			// This will be received after we sent the `StopRecording` msg
			filepath := stats.GetStopped().GetFilesink().GetFilePath()
			fmt.Println("Recording stopped. Output written to: ", filepath)
			return nil
		}
	}
}

func main() {
	if err := doRecording(); err != nil {
		panic(err)
	}
}
