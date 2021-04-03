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

// +build !privileged_tests

package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	observerAPI "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/golang/protobuf/ptypes/timestamp"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestExporter(t *testing.T) {
	// override node name for unit test.
	nodeName := nodeTypes.GetName()
	newNodeName := "my-node"
	nodeTypes.SetName(newNodeName)
	defer func() {
		nodeTypes.SetName(nodeName)
	}()
	events := []*v1.Event{
		{
			Event: &observerAPI.Flow{
				NodeName: newNodeName,
				Time:     &timestamp.Timestamp{Seconds: 1},
			},
		},
		{Timestamp: &timestamp.Timestamp{Seconds: 2}, Event: &observerAPI.AgentEvent{}},
		{Timestamp: &timestamp.Timestamp{Seconds: 3}, Event: &observerAPI.DebugEvent{}},
		{Timestamp: &timestamp.Timestamp{Seconds: 4}, Event: &observerAPI.LostEvent{}},
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	log := logrus.New()
	log.SetOutput(io.Discard)
	exporter := newExporter(log, encoder)
	ctx := context.Background()
	for _, ev := range events {
		stop, err := exporter.OnDecodedEvent(ctx, ev)
		assert.False(t, stop)
		assert.NoError(t, err)

	}
	assert.Equal(t, `{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"my-node"},"node_name":"my-node","time":"1970-01-01T00:00:01Z"}
{"agent_event":{},"node_name":"my-node","time":"1970-01-01T00:00:02Z"}
{"debug_event":{},"node_name":"my-node","time":"1970-01-01T00:00:03Z"}
{"lost_events":{},"node_name":"my-node","time":"1970-01-01T00:00:04Z"}
`, buf.String())
}
