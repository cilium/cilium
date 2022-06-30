// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"context"
	"io"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	pb "github.com/cilium/cilium/api/v1/flow"
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

func (t *testHandler) ProcessFlow(ctx context.Context, p *pb.Flow) error {
	t.ProcessCalled++
	return nil
}

func TestRegister(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	r := NewRegistry(log)

	r.Register("test", &testPlugin{})

	handlers, err := r.ConfigureHandlers(nil, Map{})
	assert.EqualValues(t, err, nil)
	assert.EqualValues(t, len(handlers.handlers), 0)

	handlers, err = r.ConfigureHandlers(nil, Map{"test": Options{}})
	assert.EqualValues(t, err, nil)
	assert.EqualValues(t, len(handlers.handlers), 1)
	assert.EqualValues(t, handlers.handlers[0].(*testHandler).InitCalled, 1)

	handlers.ProcessFlow(context.TODO(), nil)
	assert.EqualValues(t, handlers.handlers[0].(*testHandler).ProcessCalled, 1)
}
