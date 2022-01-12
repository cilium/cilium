/*
 *
 * Copyright 2019 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package xdsclient implements a full fledged gRPC client for the xDS API used
// by the xds resolver and balancer implementations.
package xdsclient

import (
	"fmt"
	"time"

	"google.golang.org/grpc/internal/grpclog"
	"google.golang.org/grpc/internal/grpcsync"
	"google.golang.org/grpc/xds/internal/xdsclient/bootstrap"
	"google.golang.org/grpc/xds/internal/xdsclient/pubsub"
	"google.golang.org/grpc/xds/internal/xdsclient/xdsresource"
)

// clientImpl is the real implementation of the xds client. The exported Client
// is a wrapper of this struct with a ref count.
//
// Implements UpdateHandler interface.
// TODO(easwars): Make a wrapper struct which implements this interface in the
// style of ccBalancerWrapper so that the Client type does not implement these
// exported methods.
type clientImpl struct {
	done   *grpcsync.Event
	config *bootstrap.Config

	controller controllerInterface

	logger *grpclog.PrefixLogger
	pubsub *pubsub.Pubsub
}

// newWithConfig returns a new xdsClient with the given config.
func newWithConfig(config *bootstrap.Config, watchExpiryTimeout time.Duration) (_ *clientImpl, retErr error) {
	c := &clientImpl{
		done:   grpcsync.NewEvent(),
		config: config,
	}

	defer func() {
		if retErr != nil {
			c.Close()
		}
	}()

	c.logger = prefixLogger(c)
	c.logger.Infof("Created ClientConn to xDS management server: %s", config.XDSServer)

	c.pubsub = pubsub.New(watchExpiryTimeout, c.logger)

	controller, err := newController(config.XDSServer, c.pubsub, c.updateValidator, c.logger)
	if err != nil {
		return nil, fmt.Errorf("xds: failed to connect to the control plane: %v", err)
	}
	c.controller = controller

	c.logger.Infof("Created")
	return c, nil
}

// BootstrapConfig returns the configuration read from the bootstrap file.
// Callers must treat the return value as read-only.
func (c *clientRefCounted) BootstrapConfig() *bootstrap.Config {
	return c.config
}

// Close closes the gRPC connection to the management server.
func (c *clientImpl) Close() {
	if c.done.HasFired() {
		return
	}
	c.done.Fire()
	// TODO: Should we invoke the registered callbacks here with an error that
	// the client is closed?

	// Note that Close needs to check for nils even if some of them are always
	// set in the constructor. This is because the constructor defers Close() in
	// error cases, and the fields might not be set when the error happens.
	if c.controller != nil {
		c.controller.Close()
	}
	if c.pubsub != nil {
		c.pubsub.Close()
	}
	c.logger.Infof("Shutdown")
}

func (c *clientImpl) filterChainUpdateValidator(fc *xdsresource.FilterChain) error {
	if fc == nil {
		return nil
	}
	return c.securityConfigUpdateValidator(fc.SecurityCfg)
}

func (c *clientImpl) securityConfigUpdateValidator(sc *xdsresource.SecurityConfig) error {
	if sc == nil {
		return nil
	}
	if sc.IdentityInstanceName != "" {
		if _, ok := c.config.CertProviderConfigs[sc.IdentityInstanceName]; !ok {
			return fmt.Errorf("identitiy certificate provider instance name %q missing in bootstrap configuration", sc.IdentityInstanceName)
		}
	}
	if sc.RootInstanceName != "" {
		if _, ok := c.config.CertProviderConfigs[sc.RootInstanceName]; !ok {
			return fmt.Errorf("root certificate provider instance name %q missing in bootstrap configuration", sc.RootInstanceName)
		}
	}
	return nil
}

func (c *clientImpl) updateValidator(u interface{}) error {
	switch update := u.(type) {
	case xdsresource.ListenerUpdate:
		if update.InboundListenerCfg == nil || update.InboundListenerCfg.FilterChains == nil {
			return nil
		}
		return update.InboundListenerCfg.FilterChains.Validate(c.filterChainUpdateValidator)
	case xdsresource.ClusterUpdate:
		return c.securityConfigUpdateValidator(update.SecurityCfg)
	default:
		// We currently invoke this update validation function only for LDS and
		// CDS updates. In the future, if we wish to invoke it for other xDS
		// updates, corresponding plumbing needs to be added to those unmarshal
		// functions.
	}
	return nil
}
