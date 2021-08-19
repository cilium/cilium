// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/api/metrics/mock"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type ApiSuite struct{}

var _ = check.Suite(&ApiSuite{})

func (a *ApiSuite) TestRateLimit(c *check.C) {
	// Since github.com/Azure/go-autorest/autorest/azure/auth v0.5.6, the
	// MSI_ENDPOINT environment variable must be set, otherwise this test will
	// fail with the error "failed to get oauth token from MSI: MSI not
	// available".
	//
	// Temporarily set the environment variable for the duration of the test,
	// using the same workaround as used in
	// github.com/Azure/go-autorest/autorest/azure/auth's tests.
	os.Setenv("MSI_ENDPOINT", "http://localhost")
	defer func() {
		os.Unsetenv("MSI_ENDPOINT")
	}()

	metricsAPI := mock.NewMockMetrics()
	client, err := NewClient("AZUREPUBLICCLOUD", "dummy-subscription", "dummy-resource-group", "", metricsAPI, 10.0, 4, true)
	c.Assert(err, check.IsNil)
	c.Assert(client, check.Not(check.IsNil))

	for i := 0; i < 10; i++ {
		client.limiter.Limit(context.TODO(), "test")
	}

	c.Assert(metricsAPI.RateLimit("test"), check.Not(check.DeepEquals), time.Duration(0))
}
