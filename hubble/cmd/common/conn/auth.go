// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conn

import (
	"context"
	"encoding/base64"

	"google.golang.org/grpc"
)

// WithBasicAuth configures basic authentication credentials for the connection.
func WithBasicAuth(username, password string) grpc.DialOption {
	return grpc.WithPerRPCCredentials(basicAuthCredentials{username: username, password: password})
}

type basicAuthCredentials struct {
	username, password string
}

func (c basicAuthCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Basic " + basicAuth(c.username, c.password),
	}, nil
}

func (c basicAuthCredentials) RequireTransportSecurity() bool {
	return true
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
