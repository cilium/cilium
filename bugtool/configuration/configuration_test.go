// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/bugtool/dump"
	"github.com/cilium/cilium/bugtool/options"
)

// This test ensures:
// * Default config validates.
// * Default config encodes/decodes without error.
func TestDefaultConfiguration(t *testing.T) {
	assert := assert.New(t)
	root := CreateDump(&options.Config{
		Topics: options.DefaultTopics,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	assert.NoError(root.Validate(ctx),
		"Validate recursively validates dump tree nodes")

	d, err := yaml.Marshal(root)
	assert.NoError(err, "Default dump configuration should marshal down to YAML")
	root, err = dump.Decode(bytes.NewReader(d))
	assert.NoError(err)
	topics := []string{}
	for _, t := range root.(*dump.Dir).Tasks {
		topics = append(topics, t.(*dump.Dir).GetName())
	}
	assert.Subset(topics, options.DefaultTopics)
}

func TestGenerateTaskName(t *testing.T) {
	assert := assert.New(t)
	assert.Equal("bpftool-map-dump-pinned_foo_bar-json", GenerateTaskName("bpftool map dump pinned /foo/bar --json"))
	assert.Equal("cilium-map-list-foo", GenerateTaskName("cilium map list --foo"))
	assert.Equal("ip-j-d-s-link", GenerateTaskName("ip -j -d -s link"))
}
