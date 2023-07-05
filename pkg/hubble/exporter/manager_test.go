// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
)

func init() {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	log = logger.WithField("test", "1")
}

func TestManager_unconfigured(t *testing.T) {
	m := NewManager(context.Background())
	err := m.Start("uidA", "name", time.Now().Add(time.Hour), nil)
	assert.ErrorContains(t, err, "unconfigured")

	err = m.Configure()
	assert.NoError(t, err)

	err = m.Start("uidB", "name", time.Now().Add(time.Hour), nil)
	assert.ErrorContains(t, err, "unconfigured")
}

func TestManager_configured(t *testing.T) {
	m := NewManager(context.Background())
	err := m.Configure(exporteroption.WithPath("/tmp/"))
	assert.NoError(t, err)

	err = m.Start("uid", "name", time.Now().Add(time.Hour), nil)
	assert.NoError(t, err)
}

func TestManager_no_duplicates(t *testing.T) {
	m := NewManager(context.Background())
	err := m.Configure(exporteroption.WithPath("/tmp/"))
	assert.NoError(t, err)

	err = m.Start("uid", "name", time.Now().Add(time.Hour), nil)
	assert.NoError(t, err)

	err = m.Start("uid", "name", time.Now().Add(time.Hour), nil)
	assert.ErrorContains(t, err, "already active")
}

func TestManager_remove_twice(t *testing.T) {
	m := NewManager(context.Background())
	err := m.Configure(exporteroption.WithPath("/tmp/"))
	assert.NoError(t, err)

	err = m.Start("uid", "name", time.Now().Add(time.Hour), nil)
	assert.NoError(t, err)

	err = m.Stop("uid")
	assert.NoError(t, err)

	err = m.Stop("uid")
	assert.ErrorContains(t, err, "doesn't exist")
}

func TestManager_ondecoded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := NewManager(ctx)
	tmp := t.TempDir()
	err := m.Configure(exporteroption.WithPath(tmp))
	assert.NoError(t, err)

	err = m.Start("uid-a", "name-a", time.Now().Add(time.Hour), nil)
	assert.NoError(t, err)

	err = m.Start("uid-b", "", time.Now().Add(time.Hour), nil)
	assert.NoError(t, err)

	_, err = m.OnDecodedEvent(context.Background(), &v1.Event{
		Event: &observerpb.Flow{
			NodeName: "test-node",
			Time:     &timestamp.Timestamp{Seconds: 1},
		},
	})
	assert.NoError(t, err)

	filepathA := filepath.Join(tmp, "uid-a", "name-a.json")
	filepathB := filepath.Join(tmp, "uid-b", ".json")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.FileExists(c, filepathA)
		assert.FileExists(c, filepathB)
	}, 10*time.Second, 10*time.Millisecond)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		f, err := os.ReadFile(filepathA)
		assert.NoError(c, err)
		assert.Equal(c, `{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"test-node"},"node_name":"test-node","time":"1970-01-01T00:00:01Z"}
`, string(f))
	}, 10*time.Second, 10*time.Millisecond)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		f, err := os.ReadFile(filepathB)
		assert.NoError(c, err)
		assert.Equal(c, `{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"test-node"},"node_name":"test-node","time":"1970-01-01T00:00:01Z"}
`, string(f))
	}, 10*time.Second, 10*time.Millisecond)

	// Keep processing uid-a when uid-b is no longer active.
	err = m.Stop("uid-b")
	assert.NoError(t, err)

	_, err = m.OnDecodedEvent(context.Background(), &v1.Event{
		Event: &observerpb.Flow{
			NodeName: "test-node",
			Time:     &timestamp.Timestamp{Seconds: 2},
		},
	})
	assert.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		f, err := os.ReadFile(filepathA)
		assert.NoError(c, err)
		assert.Equal(c, `{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"test-node"},"node_name":"test-node","time":"1970-01-01T00:00:01Z"}
{"flow":{"time":"1970-01-01T00:00:02Z","node_name":"test-node"},"node_name":"test-node","time":"1970-01-01T00:00:02Z"}
`, string(f))
	}, 10*time.Second, 10*time.Millisecond)

	// Stop processing all events when context is cancelled.
	cancel()
	_, err = m.OnDecodedEvent(context.Background(), &v1.Event{
		Event: &observerpb.Flow{
			NodeName: "test-node",
			Time:     &timestamp.Timestamp{Seconds: 3},
		},
	})
	assert.NoError(t, err)

	// There is no good access to exporter instances to flush the buffers.
	f, err := os.ReadFile(filepathA)
	assert.NoError(t, err)
	assert.Equal(t, `{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"test-node"},"node_name":"test-node","time":"1970-01-01T00:00:01Z"}
{"flow":{"time":"1970-01-01T00:00:02Z","node_name":"test-node"},"node_name":"test-node","time":"1970-01-01T00:00:02Z"}
`, string(f))

	f, err = os.ReadFile(filepathB)
	assert.NoError(t, err)
	assert.Equal(t, `{"flow":{"time":"1970-01-01T00:00:01Z","node_name":"test-node"},"node_name":"test-node","time":"1970-01-01T00:00:01Z"}
`, string(f))
}
