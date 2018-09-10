// Copyright 2018 Authors of Cilium
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

package npds

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/cilium/cilium/proxylib/proxylib"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	log "github.com/sirupsen/logrus"
)

const (
	DialBackoff = 1 * time.Second
	NPDSTypeURL = "type.googleapis.com/cilium.NetworkPolicy"
)

func StartClient(path, nodeId string) error {
	starting := true
	startErr := make(chan error) // Channel open as long as 'starting == true'

	go func() {
		unixPath := "unix://" + path
		var failReason error
		for {
			if failReason != nil {
				log.Info(failReason)
				if starting {
					startErr <- failReason
					close(startErr)
					starting = false
				}
				failReason = nil
			}

			if !starting {
				// Back off if retrying
				log.Info("NPDS: Backing off retry")
				time.Sleep(DialBackoff)
			}

			conn, err := grpc.Dial(unixPath, grpc.WithInsecure())
			if err != nil {
				failReason = fmt.Errorf("NPDS: grpc.Dial() failed: %s", err)
				continue
			}

			client := cilium.NewNetworkPolicyDiscoveryServiceClient(conn)
			stream, err := client.StreamNetworkPolicies(context.Background())
			if err != nil {
				conn.Close()
				failReason = fmt.Errorf("NPDS: Stream failed: %s", err)
				continue
			}

			// VersionInfo must be empty as we have not received anything yet.
			// ResourceNames is empty to request for all policies.
			// ResponseNonce is copied from the response, initially empty.
			req := envoy_api_v2.DiscoveryRequest{
				TypeUrl:       NPDSTypeURL,
				VersionInfo:   "",
				Node:          &envoy_api_v2_core.Node{Id: nodeId},
				ResourceNames: nil,
				ResponseNonce: "",
			}
			err = stream.Send(&req)
			if err != nil {
				stream.CloseSend()
				conn.Close()
				failReason = fmt.Errorf("NPDS: stream.Send() failed: %s", err)
				continue
			}

			// Report successful start by closing the channel
			if starting {
				close(startErr)
				starting = false
			}

			log.Debug("NPDS: Connected")

			for {
				// Receive next policy configuration. This will block until the
				// server has a new version to send, which may take a long time.
				resp, err := stream.Recv()
				if err == io.EOF {
					log.Debug("NPDS: Stream closed.")
					break
				}
				if err != nil {
					failReason = fmt.Errorf("NPDS: stream.Recv() failed: %s", err)
					break
				}
				// Validate the response
				if resp.TypeUrl != req.TypeUrl {
					msg := fmt.Sprintf("NPDS: Rejecting mismatching resource type: %s", resp.TypeUrl)
					req.ErrorDetail = &status.Status{Message: msg}
					log.Warning(msg)
				} else {
					err = proxylib.PolicyUpdate(resp)
					if err != nil {
						msg := fmt.Sprintf("NPDS: Rejecting invalid policy: %s", err)
						req.ErrorDetail = &status.Status{Message: msg}
						log.Warning(msg)
					} else {
						// Success, update the last applied version
						log.Debug("NPDS: Acking new policy version: ", resp.VersionInfo)
						req.ErrorDetail = nil
						req.VersionInfo = resp.VersionInfo
					}
				}
				req.ResponseNonce = resp.Nonce
				err = stream.Send(&req)
				if err != nil {
					failReason = fmt.Errorf("NPDS: stream.Send() failed: %s", err)
					break
				}
			}
			stream.CloseSend()
			conn.Close()
		}
	}()

	// Block until we know if the first connection try succeeded or failed
	return <-startErr
}
