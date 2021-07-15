// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Hubble

// +build !privileged_tests

package api

import (
	"context"
	"io"
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type testPlugin struct{}

func (t *testPlugin) NewHandler() Handler {
	return &testHandler{}
}

func (t *testPlugin) HelpText() string {
	return ""
}

type testHandler struct {
	ProcessCalled int
	InitCalled    int
}

func (t *testHandler) Init(registry *prometheus.Registry, options Options) error {
	t.InitCalled++
	return nil
}

func (t *testHandler) Status() string {
	return ""
}

func (t *testHandler) ProcessFlow(ctx context.Context, p *pb.Flow) {
	t.ProcessCalled++
}

func TestRegister(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	r := NewRegistry(log)

	r.Register("test", &testPlugin{})

	handlers, err := r.ConfigureHandlers(nil, Map{})
	assert.EqualValues(t, err, nil)
	assert.EqualValues(t, len(handlers), 0)

	handlers, err = r.ConfigureHandlers(nil, Map{"test": Options{}})
	assert.EqualValues(t, err, nil)
	assert.EqualValues(t, len(handlers), 1)
	assert.EqualValues(t, handlers[0].(*testHandler).InitCalled, 1)

	handlers.ProcessFlow(context.TODO(), nil)
	assert.EqualValues(t, handlers[0].(*testHandler).ProcessCalled, 1)
}
