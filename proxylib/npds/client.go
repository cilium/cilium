// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package npds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/proxylib/proxylib"
)

const (
	DialDelay    = 100 * time.Millisecond
	BackOffLimit = 100 // Max 100 times DialDelay
	NPDSTypeURL  = "type.googleapis.com/cilium.NetworkPolicy"
)

type Client struct {
	updater proxylib.PolicyUpdater
	mutex   lock.Mutex
	nodeId  string
	path    string
	conn    *grpc.ClientConn
	stream  grpc.ClientStream
	closing bool
}

func (c *Client) Close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.closing {
		logrus.Debugf("NPDS: Client %s closing on %s", c.nodeId, c.path)
		c.closing = true
		if c.stream != nil {
			c.stream.CloseSend()
		}
		if c.conn != nil {
			c.conn.Close()
		}
	}
}

func (c *Client) Path() string {
	return c.path
}

func NewClient(path, nodeId string, updater proxylib.PolicyUpdater) proxylib.PolicyClient {
	if path == "" {
		return nil
	}
	c := &Client{
		updater: updater,
		path:    path,
		nodeId:  nodeId,
	}
	logrus.Debugf("NPDS: Client %s starting on %s", c.nodeId, c.path)

	// These are used to return error if the 1st try fails
	// Only used for testing and logging, as we keep on trying anyway.
	startErr := make(chan error) // Channel open as long as 'starting == true'

	BackOff := backoff.Exponential{
		Min:  DialDelay,
		Max:  BackOffLimit * DialDelay,
		Name: "proxylib NPDS client",
	}

	go func() {
		starting := true
		backOff := BackOff
		for {
			err := c.Run(func() {
				// Report successful start on the first try by closing the channel
				if starting {
					close(startErr)
					starting = false
				}
				logrus.Debugf("NPDS: Client %s connected on %s", c.nodeId, c.path)
			})
			c.mutex.Lock()
			closing := c.closing
			c.mutex.Unlock()

			if err != nil {
				logrus.Debug(err)
				if starting {
					startErr <- err
					close(startErr)
					starting = false
				}
			} else {
				// Reset backoff after successful start
				backOff.Reset()
			}

			if closing {
				break
			}

			// Back off before retrying
			backOff.Wait(context.TODO())
		}
	}()

	// Block until we know if the first connection try succeeded or failed
	_ = <-startErr
	return c
}

func (c *Client) Run(connected func()) (err error) {
	unixPath := "unix://" + c.path

	defer func() {
		// Recover from any possible panics
		if r := recover(); r != nil {
			err = fmt.Errorf("NPDS Client %s: Panic: %v", c.nodeId, r)
		}
	}()

	//
	// WithInsecure() is safe here because we are connecting to a Unix-domain socket,
	// data of whch is never on the wire and security for which can be managed with file permissions.
	//
	conn, err := grpc.Dial(unixPath, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("NPDS: Client %s grpc.Dial() on %s failed: %s", c.nodeId, c.path, err)
	}
	client := cilium.NewNetworkPolicyDiscoveryServiceClient(conn)
	stream, err := client.StreamNetworkPolicies(context.Background())
	if err != nil {
		conn.Close()
		return fmt.Errorf("NPDS: Client %s stream failed on %s: %s", c.nodeId, c.path, err)
	}
	c.mutex.Lock()
	c.conn = conn
	c.stream = stream
	c.mutex.Unlock()
	defer func() {
		c.mutex.Lock()
		c.stream.CloseSend()
		c.conn.Close()
		c.mutex.Unlock()
	}()

	// VersionInfo must be empty as we have not received anything yet.
	// ResourceNames is empty to request for all policies.
	// ResponseNonce is copied from the response, initially empty.
	req := envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       NPDSTypeURL,
		VersionInfo:   "",
		Node:          &envoy_config_core.Node{Id: c.nodeId},
		ResourceNames: nil,
		ResponseNonce: "",
	}
	err = stream.Send(&req)
	if err != nil {
		return fmt.Errorf("NPDS: Client %s stream.Send() failed on %s: %s", c.nodeId, c.path, err)
	}

	connected()

	for {
		// Receive next policy configuration. This will block until the
		// server has a new version to send, which may take a long time.
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			logrus.Debugf("NPDS: Client %s stream on %s closed.", c.nodeId, c.path)
			break
		}
		if err != nil {
			return fmt.Errorf("NPDS: Client %s stream.Recv() on %s failed: %s", c.nodeId, c.path, err)
		}

		// Validate the response
		if resp.TypeUrl != req.TypeUrl {
			msg := fmt.Sprintf("NPDS: Client %s rejecting mismatching resource type on %s: %s", c.nodeId, c.path, resp.TypeUrl)
			req.ErrorDetail = &status.Status{Message: msg}
			logrus.Warning(msg)
		} else {
			err = c.updater.PolicyUpdate(resp)
			if err != nil {
				msg := fmt.Sprintf("NPDS: Client %s rejecting invalid policy on %s: %s", c.nodeId, c.path, err)
				req.ErrorDetail = &status.Status{Message: msg}
				logrus.Warning(msg)
			} else {
				// Success, update the last applied version
				logrus.Debugf("NPDS: Client %s acking new policy version on %s: %s", c.nodeId, c.path, resp.VersionInfo)
				req.ErrorDetail = nil
				req.VersionInfo = resp.VersionInfo
			}
		}
		req.ResponseNonce = resp.Nonce
		err = stream.Send(&req)
		if err != nil {
			return fmt.Errorf("NPDS: Client %s stream.Send() failed on %s: %s", c.nodeId, c.path, err)
		}
	}
	return nil
}
