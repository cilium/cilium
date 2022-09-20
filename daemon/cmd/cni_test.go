// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path"
	"testing"

	"github.com/cilium/cilium/pkg/option"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func TestInstallCNIConfFile(t *testing.T) {
	workdir := t.TempDir()
	opts := &option.DaemonConfig{
		Debug:                          false,
		CNILogFile:                     "/opt\"/cni.log", // test escaping :-)
		CNIChainingMode:                "none",
		CNIExclusive:                   true,
		WriteCNIConfigurationWhenReady: path.Join(workdir, "05-cilium.conflist"),
	}

	touch(t, workdir, "other.conflist")
	touch(t, workdir, "05-cilium.conf") // older config file we no longer create

	err := installCNIConfFile(opts)
	assert.NoError(t, err)

	filenames := ls(t, workdir)

	assert.ElementsMatch(t, filenames, []string{
		"05-cilium.conflist",
		"other.conflist.cilium_bak",
	})

	data, err := os.ReadFile(path.Join(workdir, "05-cilium.conflist"))
	assert.NoError(t, err)
	val := gjson.GetBytes(data, "plugins.0.type")
	assert.Equal(t, val.String(), "cilium-cni")

}

func TestMergeExistingAWSConfig(t *testing.T) {
	opts := &option.DaemonConfig{
		Debug:           false,
		CNILogFile:      "/opt\"/cni.log", // test escaping :-)
		CNIChainingMode: "aws-cni",
	}

	workdir := t.TempDir()
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

	res, err := renderCNIConf(opts, workdir)
	assert.NoError(t, err)

	val := gjson.GetBytes(res, `plugins.#`)
	assert.Equal(t, val.Int(), int64(3))

	val = gjson.GetBytes(res, `plugins.@reverse.0.type`)
	assert.Equal(t, val.String(), "cilium-cni")

}

func TestRenderCNIConf(t *testing.T) {
	opts := &option.DaemonConfig{
		Debug:      false,
		CNILogFile: "/opt\"/cni.log", // test escaping :-)
	}
	// check that all templates compile
	for mode := range cniConfigs {
		opts.CNIChainingMode = mode
		conf, err := renderCNIConf(opts, "/")
		assert.NoError(t, err)
		res := gjson.GetBytes(conf, `plugins.#(type=="cilium-cni").log-file`)
		assert.True(t, res.Exists(), mode)
		assert.Equal(t, res.String(), "/opt\"/cni.log", mode)
	}

	assert.Equal(t,
		string(renderCNITemplate(awsCNIEntry, opts)),
		`
{
	"type": "cilium-cni",
	"enable-debug": false,
	"log-file": "/opt\"/cni.log"
}
`,
	)

}

func TestFindFile(t *testing.T) {
	workdir := t.TempDir()

	_, err := findFile(workdir, []string{"a", "b"})
	assert.Error(t, err)

	touch(t, workdir, "b")

	found, _ := findFile(workdir, []string{"a", "b"})
	assert.Equal(t, found, path.Join(workdir, "b"))

	touch(t, workdir, "a")
	found, _ = findFile(workdir, []string{"a", "b"})
	assert.Equal(t, found, path.Join(workdir, "a"))
}

func TestCleanupOtherCNI(t *testing.T) {

	workdir := t.TempDir()

	for _, name := range []string{
		"01-someoneelse.conf",
		"99-test.conflist",
		"42-keep.json",
		"44-dontkeep.json",
	} {
		touch(t, workdir, name)
	}

	if err := cleanupOtherCNI(workdir, "42-keep.json"); err != nil {
		t.Fatal(err)
	}

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
