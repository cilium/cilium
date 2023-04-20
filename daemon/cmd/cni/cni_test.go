// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cni

import (
	"os"
	"path"
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

func TestMergeExistingAWSConfig(t *testing.T) {
	workdir := t.TempDir()
	cfg := Config{
		CNILogFile:            `/opt"/cni.log`,
		CNIChainingMode:       "aws-cni",
		CNIExclusive:          true,
		WriteCNIConfWhenReady: path.Join(workdir, "05-cilium.conflist"),
	}
	c := newConfigManager(logging.DefaultLogger, cfg, false)

	// write an "existing" AWS config
	existing := `
{
	"cniVersion": "0.4.0",
	"name": "foo",
	"plugins": [
		{
			"type": "a"
		},
		{
			"type": "b"
		}
	]
}
`
	assert.NoError(t, os.WriteFile(path.Join(workdir, "10-aws.conflist"), []byte(existing), 0644))

	res, err := c.renderCNIConf()
	assert.NoError(t, err)

	val := gjson.GetBytes(res, `plugins.#`)
	assert.Equal(t, int64(3), val.Int())

	val = gjson.GetBytes(res, `plugins.@reverse.0.type`)
	assert.Equal(t, "cilium-cni", val.String())

}

func TestRenderCNIConf(t *testing.T) {
	cfg := Config{
		CNILogFile:      `/opt"/cni.log`,
		CNIChainingMode: "aws-cni",
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

	assert.Equal(t,
		`
{
	"type": "cilium-cni",
	"enable-debug": false,
	"log-file": "/opt\"/cni.log"
}
`,
		string(c.renderCNITemplate(awsCNIEntry)),
	)

}

func TestFindFile(t *testing.T) {
	workdir := t.TempDir()

	_, err := findFile(workdir, []string{"a", "b"})
	assert.Error(t, err)

	touch(t, workdir, "b")

	found, _ := findFile(workdir, []string{"a", "b"})
	assert.Equal(t, path.Join(workdir, "b"), found)

	touch(t, workdir, "a")
	found, _ = findFile(workdir, []string{"a", "b"})
	assert.Equal(t, path.Join(workdir, "a"), found)
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
