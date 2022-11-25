// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestInstallCNIConfFile(t *testing.T) {
	workdir := t.TempDir()
	readCNIDir := t.TempDir()
	cases := []struct {
		name                string
		opts                *option.DaemonConfig
		inputFiles          map[string]string
		expectedOutputFiles map[string]string
		expectedFailure     bool
	}{
		{
			name: "render the CNI conf file according to CNIChainingMode",
			opts: &option.DaemonConfig{
				Debug:                          false,
				CNILogFile:                     "/opt\"/cni.log", // test escaping :-)
				CNIChainingMode:                "none",
				CNIExclusive:                   true,
				WriteCNIConfigurationWhenReady: path.Join(workdir, "05-cilium.conflist"),
			},
			inputFiles: map[string]string{
				path.Join(workdir, "other.conflist"): `{}`,
				path.Join(workdir, "05-cilium.conf"): `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
			},
			expectedOutputFiles: map[string]string{
				"05-cilium.conflist": `
{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "plugins": [
    {
       "type": "cilium-cni",
       "enable-debug": false,
       "log-file": "/opt\"/cni.log"
    }
  ]
}`,
				"other.conflist.cilium_bak": `{}`,
			},
		},
		{
			name: "write ReadCNIConfiguration directly into WriteCNIConfigurationWhenReady when WriteCNIConfigurationChainingMode = false",
			opts: &option.DaemonConfig{
				Debug:                             false,
				CNIChainingMode:                   "generic-veth",
				CNIExclusive:                      true,
				WriteCNIConfigurationWhenReady:    path.Join(workdir, "05-cilium.conflist"),
				WriteCNIConfigurationChainingMode: false,
				ReadCNIConfiguration:              path.Join(readCNIDir, "05-cilium-origin.conflist"),
			},
			inputFiles: map[string]string{
				path.Join(workdir, "other.conflist"): `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
				path.Join(readCNIDir, "05-cilium-origin.conflist"): `
{
  "cniVersion": "0.3.1",
  "name": "generic-veth",
  "plugins": [
    {
       "name": "calico",
       "type": "calico"
    },
    {
	   "name": "cilium-cni",
	   "type": "cilium-cni"
    }
  ]
}`,
			},
			expectedOutputFiles: map[string]string{
				"05-cilium.conflist": `
{
  "cniVersion": "0.3.1",
  "name": "generic-veth",
  "plugins": [
    {
       "name": "calico",
       "type": "calico"
    },
    {
	   "name": "cilium-cni",
	   "type": "cilium-cni"
    }
  ]
}`,
				"other.conflist.cilium_bak": `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
			},
		},
		{
			name: "write ReadCNIConfiguration with CNIChainingMode into WriteCNIConfigurationWhenReady when WriteCNIConfigurationChainingMode = true and no other CNI configuration files exist",
			opts: &option.DaemonConfig{
				Debug:                             false,
				CNIChainingMode:                   "generic-veth",
				CNIExclusive:                      true,
				WriteCNIConfigurationWhenReady:    path.Join(workdir, "05-cilium.conflist"),
				WriteCNIConfigurationChainingMode: true,
				ReadCNIConfiguration:              path.Join(readCNIDir, "05-cilium-origin.conf"),
			},
			inputFiles: map[string]string{
				path.Join(workdir, "other.conflist.cilium_bak"): `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
				path.Join(readCNIDir, "05-cilium-origin.conf"): `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
			},
			expectedOutputFiles: map[string]string{
				"05-cilium.conflist": `
{
  "cniVersion": "0.3.1",
  "name": "generic-veth",
  "plugins": [
    {
       "name": "cilium-cni",
       "type": "cilium-cni"
    }
  ]
}`,
				"other.conflist.cilium_bak": `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
			},
		},
		{
			name: "insert ReadCNIConfiguration into the default CNI plugin and write it into WriteCNIConfigurationWhenReady when WriteCNIConfigurationChainingMode = true",
			opts: &option.DaemonConfig{
				Debug:                             false,
				CNIChainingMode:                   "generic-veth",
				CNIExclusive:                      true,
				WriteCNIConfigurationWhenReady:    path.Join(workdir, "05-cilium.conflist"),
				WriteCNIConfigurationChainingMode: true,
				ReadCNIConfiguration:              path.Join(readCNIDir, "05-cilium-origin.conf"),
			},
			inputFiles: map[string]string{
				path.Join(workdir, "default.conf"): `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
				path.Join(readCNIDir, "05-cilium-origin.conf"): `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
			},
			expectedOutputFiles: map[string]string{
				"05-cilium.conflist": `
{
  "cniVersion": "0.3.1",
  "name": "generic-veth",
  "plugins": [
    {
       "name": "calico",
       "type": "calico"
    },
    {
	   "name": "cilium-cni",
	   "type": "cilium-cni"
    }
  ]
}`,
				"default.conf.cilium_bak": `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
			},
		},
		{
			name: "insert ReadCNIConfiguration into the file specified by DefaultCNIConfiguration and write it into WriteCNIConfigurationWhenReady when WriteCNIConfigurationChainingMode = true",
			opts: &option.DaemonConfig{
				Debug:                             false,
				CNIChainingMode:                   "generic-veth",
				CNIExclusive:                      true,
				WriteCNIConfigurationWhenReady:    path.Join(workdir, "05-cilium.conflist"),
				WriteCNIConfigurationChainingMode: true,
				ReadCNIConfiguration:              path.Join(readCNIDir, "05-cilium-origin.conf"),
				DefaultCNIConfiguration:           path.Join(workdir, "default.conf"),
			},
			inputFiles: map[string]string{
				path.Join(workdir, "default.conf"): `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
				path.Join(workdir, "another.conf"): `
{
      "cniVersion": "0.3.0",
      "name": "portmap",
      "type": "portmap"
}`,
				path.Join(readCNIDir, "05-cilium-origin.conf"): `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
			},
			expectedOutputFiles: map[string]string{
				"05-cilium.conflist": `
{
  "cniVersion": "0.3.1",
  "name": "generic-veth",
  "plugins": [
    {
       "name": "calico",
       "type": "calico"
    },
    {
	   "name": "cilium-cni",
	   "type": "cilium-cni"
    }
  ]
}`,
				"default.conf.cilium_bak": `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
				"another.conf.cilium_bak": `
{
      "cniVersion": "0.3.0",
      "name": "portmap",
      "type": "portmap"
}`,
			},
		},
		{
			name: "insert ReadCNIConfiguration into the file specified by DefaultCNIConfiguration and write it into WriteCNIConfigurationWhenReady when WriteCNIConfigurationChainingMode = true and CNIExclusive = false",
			opts: &option.DaemonConfig{
				Debug:                             false,
				CNIChainingMode:                   "generic-veth",
				CNIExclusive:                      false,
				WriteCNIConfigurationWhenReady:    path.Join(workdir, "05-cilium.conflist"),
				WriteCNIConfigurationChainingMode: true,
				ReadCNIConfiguration:              path.Join(readCNIDir, "05-cilium-origin.conf"),
				DefaultCNIConfiguration:           path.Join(workdir, "default.conf"),
			},
			inputFiles: map[string]string{
				path.Join(workdir, "default.conf"): `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
				path.Join(workdir, "another.conf"): `
{
      "cniVersion": "0.3.0",
      "name": "portmap",
      "type": "portmap"
}`,
				path.Join(readCNIDir, "05-cilium-origin.conf"): `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
			},
			expectedOutputFiles: map[string]string{
				"05-cilium.conflist": `
{
  "cniVersion": "0.3.1",
  "name": "generic-veth",
  "plugins": [
    {
       "name": "calico",
       "type": "calico"
    },
    {
	   "name": "cilium-cni",
	   "type": "cilium-cni"
    }
  ]
}`,
				"default.conf.cilium_bak": `
{
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
				"another.conf": `
{
      "cniVersion": "0.3.0",
      "name": "portmap",
      "type": "portmap"
}`,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_ = os.RemoveAll(workdir)
			_ = os.RemoveAll(readCNIDir)
			_ = os.MkdirAll(workdir, 0o777)
			_ = os.MkdirAll(readCNIDir, 0o777)
			for filename, contents := range c.inputFiles {
				err := os.WriteFile(filename, []byte(contents), 0o644)
				if err != nil {
					t.Fatal(err)
				}
			}

			for i := 0; i < 2; i++ {
				// i == 0; it is to simulate the first starting
				// i == 1; it is to simulate the restarting of agent
				err := installCNIConfFile(c.opts)
				if (c.expectedFailure && err == nil) || (!c.expectedFailure && err != nil) {
					t.Fatalf("expected failure: %t, got %v", c.expectedFailure, err)
				}

				filenames := ls(t, workdir)

				expectedFileNames := make([]string, 0)
				for filename, _ := range c.expectedOutputFiles {
					expectedFileNames = append(expectedFileNames, filename)
				}
				assert.ElementsMatch(t, filenames, expectedFileNames)

				for filename, value := range c.expectedOutputFiles {
					data, err := os.ReadFile(path.Join(workdir, filename))
					assert.NoError(t, err)
					require.JSONEqf(t, value, string(data), "expected %s, got %s", value, string(data))
				}
			}

		})
	}

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

func TestGetDefaultCNINetwork(t *testing.T) {
	tempDir := t.TempDir()

	cases := []struct {
		name            string
		dir             string
		inFilename      string
		outFilename     string
		fileContents    string
		expectedFailure bool
	}{
		{
			name:            "inexistent directory",
			dir:             "/inexistent/directory",
			expectedFailure: true,
		},
		{
			name:            "empty directory",
			dir:             tempDir,
			expectedFailure: true,
		},
		{
			// Only .conf and .conflist files are detectable
			name:            "undetectable file",
			dir:             tempDir,
			expectedFailure: true,
			inFilename:      "undetectable.file",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
		},
		{
			name:            "empty file",
			dir:             tempDir,
			expectedFailure: true,
			inFilename:      "empty.conf",
		},
		{
			name:            "regular file",
			dir:             tempDir,
			expectedFailure: false,
			inFilename:      "regular.conf",
			outFilename:     "regular.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
		},
		{
			name:            "another regular file",
			dir:             tempDir,
			expectedFailure: false,
			inFilename:      "regular2.conf",
			outFilename:     "regular.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.fileContents != "" {
				err := os.WriteFile(filepath.Join(c.dir, c.inFilename), []byte(c.fileContents), 0o644)
				if err != nil {
					t.Fatal(err)
				}
			}

			result, _, err := getDefaultCNINetworkList(c.dir)
			if (c.expectedFailure && err == nil) || (!c.expectedFailure && err != nil) {
				t.Fatalf("expected failure: %t, got %v", c.expectedFailure, err)
			}

			if c.fileContents != "" && c.outFilename != "" {
				if c.outFilename != filepath.Base(result) {
					t.Fatalf("expected %s, got %s", c.outFilename, result)
				}
			}
		})
	}
}

func TestInsertConfList(t *testing.T) {
	cases := []struct {
		name            string
		cniChainMode    string
		original        string
		inserted        string
		expected        string
		expectedFailure bool
	}{
		{
			name:         "insert the plugin into the file suffixed with .conf",
			cniChainMode: "generic-veth",
			original: `
 {
      "cniVersion": "0.2.1",
      "name": "calico",
      "type": "calico"
}`,
			inserted: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}
`,
			expected: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins": [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}`,
		},
		{
			name:         "insert the plugin into the file suffixed with .conflist",
			cniChainMode: "generic-veth",
			original: `
 {
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni",
			"enable-debug": true
        }
    ]
}`,
			inserted: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}
`,
			expected: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}`,
		},
		{
			name:         "insert the plugins suffixed with .conflist into the file suffixed with .conflist",
			cniChainMode: "generic-veth",
			original: `
 {
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "isto-cni",
            "type": "isto-cni"
        }
    ]
}`,
			inserted: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "portmap",
            "type": "portmap"
        },
        {
            "name": "cilium-cni",
            "type": "cilium-cni",
			"enable-debug": true
        }
    ]
}
`,
			expected: `
{
    "cniVersion": "0.3.1",
    "name": "generic-veth",
    "plugins":
    [
        {
            "name": "calico",
            "type": "calico"
        },
        {
            "name": "isto-cni",
            "type": "isto-cni"
        },
        {
            "name": "portmap",
            "type": "portmap"
        },
        {
            "enable-debug": true,
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := insertConfList(c.cniChainMode, []byte(c.original), []byte(c.inserted))
			if (c.expectedFailure && err == nil) || (!c.expectedFailure && err != nil) {
				t.Fatalf("expected failure: %t, got %v", c.expectedFailure, err)
			}

			if c.expected != "" {
				require.JSONEqf(t, c.expected, string(result), "expected %s, got %s", c.expected, string(result))
			}
		})
	}
}

func TestGetCNINetworkListFromFile(t *testing.T) {
	tempDir := t.TempDir()

	cases := []struct {
		name            string
		inFilename      string
		fileContents    string
		outFileContents string
		expectedFailure bool
	}{
		{
			name:       "the correct content for the file suffixed with .conf",
			inFilename: "cilium.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni",
	"type": "cilium-cni"
}`,
			outFileContents: `
 {
    "cniVersion": "0.3.1",
    "name": "cilium-cni",
    "plugins":
    [
        {
            "cniVersion": "0.3.1",
            "name": "cilium-cni",
            "type": "cilium-cni"
        }
    ]
}
`,
			expectedFailure: false,
		},
		{
			name:       "the correct content for the file suffixed with .conflist",
			inFilename: "cilium.conflist",
			fileContents: `
{
  "cniVersion": "0.2.0",
  "name": "generic-veth",
  "plugins": [
    {
      "name": "cilium",
      "type": "cilium-cni"
    }
  ]
}`,
			outFileContents: `
{
  "cniVersion": "0.2.0",
  "name": "generic-veth",
  "plugins": [
    {
      "name": "cilium",
      "type": "cilium-cni"
    }
  ]
}
`,
			expectedFailure: false,
		},
		{
			name:            "unexpected content in the file suffixed with .conf",
			expectedFailure: true,
			inFilename:      "cilium.conf",
			fileContents: `
{
	"cniVersion": "0.3.1",
	"name": "cilium-cni"
}`,
		},
		{
			name:            "no plugins in the file suffixed with .conflist",
			expectedFailure: true,
			inFilename:      "cilium.conflist",
			fileContents: `
{
  "cniVersion": "0.2.0",
  "name": "generic-veth",
  "plugins": [
  ]
}
`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.fileContents != "" {
				err := os.WriteFile(filepath.Join(tempDir, c.inFilename), []byte(c.fileContents), 0o644)
				if err != nil {
					t.Fatal(err)
				}
			}

			result, err := getCNINetworkListFromFile(filepath.Join(tempDir, c.inFilename))
			if (c.expectedFailure && err == nil) || (!c.expectedFailure && err != nil) {
				t.Fatalf("expected failure: %t, got %v", c.expectedFailure, err)
			}

			if c.expectedFailure == false {
				require.JSONEqf(t, c.outFileContents, string(result), "expected %s, got %s", c.outFileContents, string(result))
			}
		})
	}
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
