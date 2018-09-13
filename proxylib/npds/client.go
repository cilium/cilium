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
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

const (
	DialDelay    = 100 * time.Millisecond
	BackOffLimit = 100 // Max 100 times DialDelay
	NPDSTypeURL  = "type.googleapis.com/cilium.NetworkPolicy"
)

// Mutex is used to protect clients
var mutex lock.Mutex

var clients map[string]string // Set of running clients, map from nodeId to path

func StartClient(path, nodeId string) (err error) {
	mutex.Lock()
	defer mutex.Unlock()
	if clients == nil {
		clients = make(map[string]string)
	}
	if oldPath, ok := clients[nodeId]; ok && oldPath == path {
		log.Infof("NPDS: Client %s already running on %s, not starting again.", nodeId, path)
		return nil
	}
	clients[nodeId] = path

	log.Infof("NPDS: Client %s starting on %s", nodeId, path)

	// These are used to return error if the 1st try fails
	// Only used for testing and logging, as we keep on trying anyway.
	startErr := make(chan error) // Channel open as long as 'starting == true'

	go func() {
		starting := true
		backOff := 1
		for {
			err = client(path, nodeId, func() {
				// Report successful start on the first try by closing the channel
				if starting {
					close(startErr)
					starting = false
				}
				log.Infof("NPDS: Client %s connected on %s", nodeId, path)
			})

			if err != nil {
				backOff *= 2
				if backOff > BackOffLimit {
					backOff = BackOffLimit
				}
				log.Info(err)
				if starting {
					startErr <- err
					close(startErr)
					starting = false
				}
			} else {
				backOff = 1
			}

			// Back off before retrying
			delay := DialDelay * time.Duration(backOff)
			log.Infof("NPDS: Client %s backing off retry on %s for %v", nodeId, path, delay)
			time.Sleep(delay)
		}
	}()

	// Block until we know if the first connection try succeeded or failed
	err = <-startErr
	return err
}

func client(path, nodeId string, connected func()) (err error) {
	unixPath := "unix://" + path

	defer func() {
		// Recover from any possible panics
		if r := recover(); r != nil {
			err = fmt.Errorf("NPDS Client %s: Panic: %v", nodeId, r)
		}
	}()

	var conn *grpc.ClientConn
	//
	// WithInsecure() is safe here because we are connecting to a Unix-domain socket,
	// data of whch is never on the wire and security for which can be managed with file permissions.
	//
	conn, err = grpc.Dial(unixPath, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("NPDS: Client %s grpc.Dial() on %s failed: %s", nodeId, path, err)
	}
	defer conn.Close()

	client := cilium.NewNetworkPolicyDiscoveryServiceClient(conn)
	stream, err := client.StreamNetworkPolicies(context.Background())
	if err != nil {
		return fmt.Errorf("NPDS: Client %s stream failed on %s: %s", nodeId, path, err)
	}
	defer stream.CloseSend()

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
		return fmt.Errorf("NPDS: Client %s stream.Send() failed on %s: %s", nodeId, path, err)
	}

	connected()

	for {
		// Receive next policy configuration. This will block until the
		// server has a new version to send, which may take a long time.
		resp, err := stream.Recv()
		if err == io.EOF {
			log.Debugf("NPDS: Client %s stream on %s closed.", nodeId, path)
			break
		}
		if err != nil {
			return fmt.Errorf("NPDS: Client %s stream.Recv() on %s failed: %s", nodeId, path, err)
		}
		// Validate the response
		if resp.TypeUrl != req.TypeUrl {
			msg := fmt.Sprintf("NPDS: Client %s rejecting mismatching resource type on %s: %s", nodeId, path, resp.TypeUrl)
			req.ErrorDetail = &status.Status{Message: msg}
			log.Warning(msg)
		} else {
			err = proxylib.PolicyUpdate(resp)
			if err != nil {
				msg := fmt.Sprintf("NPDS: Client %s rejecting invalid policy on %s: %s", nodeId, path, err)
				req.ErrorDetail = &status.Status{Message: msg}
				log.Warning(msg)
			} else {
				// Success, update the last applied version
				log.Debugf("NPDS: Client %s acking new policy version on %s: %s", nodeId, path, resp.VersionInfo)
				req.ErrorDetail = nil
				req.VersionInfo = resp.VersionInfo
			}
		}
		req.ResponseNonce = resp.Nonce
		err = stream.Send(&req)
		if err != nil {
			return fmt.Errorf("NPDS: Client %s stream.Send() failed on %s: %s", nodeId, path, err)
		}
	}
	return nil
}
