// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cni

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/logging"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func TestInstallCNIConfFile(t *testing.T) {
	workdir := t.TempDir()
	cfg := Config{
		CNILogFile:            `/opt"/cni.log`,
		CNIChainingMode:       "none",
		CNIExclusive:          true,
		WriteCNIConfWhenReady: path.Join(workdir, "05-cilium.conflist"),
	}
	c := newConfigManager(logging.DefaultLogger, cfg, false)

	touch(t, workdir, "other.conflist")
	touch(t, workdir, "05-cilium.conf") // older config file we no longer create

	err := c.setupCNIConfFile()
	assert.NoError(t, err)

	filenames := ls(t, workdir)

	assert.ElementsMatch(t, filenames, []string{
		"05-cilium.conflist",
		"05-cilium.conf.cilium_bak",
		"other.conflist.cilium_bak",
	})

	data, err := os.ReadFile(path.Join(workdir, "05-cilium.conflist"))
	assert.NoError(t, err)
	val := gjson.GetBytes(data, "plugins.0.type")
	assert.Equal(t, "cilium-cni", val.String())

}

func TestRenderCNIConfUnchained(t *testing.T) {
	cfg := Config{
		CNILogFile: `/opt"/cni.log`,
	}
	c := newConfigManager(logging.DefaultLogger, cfg, false)
	// check that all templates compile
	for mode := range cniConfigs {
		c.config.CNIChainingMode = mode
		conf, err := c.renderCNIConf()
		assert.NoError(t, err)
		res := gjson.GetBytes(conf, `plugins.#(type=="cilium-cni").log-file`)
		assert.True(t, res.Exists(), mode)
		assert.Equal(t, `/opt"/cni.log`, res.String(), mode)
	}
}

func TestRenderCNIConfChained(t *testing.T) {
	cfg := Config{
		CNILogFile:        `/opt"/cni.log`,
		CNIChainingMode:   "testing",
		CNIChainingTarget: "another-network",
	}

	c := newConfigManager(logging.DefaultLogger, cfg, false)
	for _, tc := range []struct {
		name            string
		cniConf         string
		cniConfFilename string // filename to write
		expected        string
	}{
		// Test that we return error when no network is found
		{
			name: "empty",
		},

		// Test on a sample AWS configuration
		{
			name: "aws",
			cniConf: `
{
  "cniVersion": "0.4.0",
  "name": "another-network",
  "disableCheck": true,
  "plugins": [
    {
      "type": "aws-cni"
    },
    {
      "type": "egress-v4-cni"
    },
    {
      "type": "portmap"
    }
  ]
}
`,
			cniConfFilename: "10-aws.conflist",
			expected: `
{
  "cniVersion": "0.4.0",
  "name": "another-network",
  "disableCheck": true,
  "plugins": [
    {
      "type": "aws-cni"
    },
    {
      "type": "egress-v4-cni"
    },
    {
      "type": "portmap"
    },
	{
		"type": "cilium-cni",
		"chaining-mode": "testing",
		"enable-debug": false,
		"log-file": "/opt\"/cni.log"

	}
  ]
}
`,
		},

		// Test that we can upgrade a .conf to a .conflist
		{
			name: "cni-conf",
			cniConf: `
{
  "cniVersion": "0.4.0",
  "name": "another-network",
  "type": "sample",
  "foo": "bar"
}
`,
			cniConfFilename: "10-another.conf",
			expected: `
{
  "cniVersion": "0.4.0",
  "name": "another-network",
  "plugins": [
    {
	  "cniVersion": "0.4.0",
	  "name": "another-network",
      "type": "sample",
	  "foo": "bar"
    },
	{
		"type": "cilium-cni",
		"chaining-mode": "testing",
		"enable-debug": false,
		"log-file": "/opt\"/cni.log"

	}
  ]
}
`,
		},
		// Test that we handle the (unlikely) case that we're already injected
		{
			name: "already-existing",
			cniConf: `
{
  "cniVersion": "0.4.0",
  "name": "another-network",
  "disableCheck": true,
  "plugins": [
    {
      "type": "aws-cni"
    },
    {
      "type": "cilium-cni"
    },
    {
      "type": "portmap"
    }
  ]
}
`,
			cniConfFilename: "10-existing.conflist",
			expected: `
{
  "cniVersion": "0.4.0",
  "name": "another-network",
  "disableCheck": true,
  "plugins": [
    {
      "type": "aws-cni"
    },
    {
		"type": "cilium-cni",
		"chaining-mode": "testing",
		"enable-debug": false,
		"log-file": "/opt\"/cni.log"

	},
	{
      "type": "portmap"
    }
  ]
}
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			c.cniConfDir = workDir

			if tc.cniConf != "" {
				err := os.WriteFile(filepath.Join(workDir, tc.cniConfFilename), []byte(tc.cniConf), 0o644)
				assert.NoError(t, err)
			}

			result, err := c.renderCNIConf()
			if tc.expected == "" {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(result))
		})
	}
}

func TestCleanupOtherCNI(t *testing.T) {
	workdir := t.TempDir()
	cfg := Config{
		CNIExclusive:          true,
		WriteCNIConfWhenReady: path.Join(workdir, "42-keep.json"),
	}
	c := newConfigManager(logging.DefaultLogger, cfg, false)

	for _, name := range []string{
		"01-someoneelse.conf",
		"99-test.conflist",
		"42-keep.json",
		"44-dontkeep.json",
	} {
		touch(t, workdir, name)
	}

	err := c.cleanupOtherCNI()
	assert.NoError(t, err)

	filenames := ls(t, workdir)
	assert.ElementsMatch(t, filenames, []string{
		"01-someoneelse.conf.cilium_bak",
		"99-test.conflist.cilium_bak",
		"42-keep.json",
		"44-dontkeep.json.cilium_bak",
	})
}

func touch(t *testing.T, dir, name string) {
	f, err := os.Create(path.Join(dir, name))
	assert.NoError(t, err)
	f.Close()
}

func ls(t *testing.T, dir string) []string {
	files, err := os.ReadDir(dir)
	assert.NoError(t, err)

	filenames := []string{}
	for _, f := range files {
		filenames = append(filenames, f.Name())
	}
	return filenames
}
