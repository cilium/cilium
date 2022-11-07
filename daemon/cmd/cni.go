// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/option"

	"github.com/fsnotify/fsnotify"
	"github.com/google/renameio"
	"github.com/tidwall/sjson"
)

// Some functions around managing the CNI configuration file
//
// By default, we write the CNI configuration file to disk after the
// daemon has successfully started up.

// cniConfigs are the default configurations, per chaining mode
var cniConfigs map[string]string = map[string]string{
	// the default
	"none": `
{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "plugins": [
    {
       "type": "cilium-cni",
       "enable-debug": {{.Debug | js }},
       "log-file": "{{.LogFile | js }}"
    }
  ]
}`,

	"flannel": `
{
  "cniVersion": "0.3.1",
  "name": "flannel",
  "plugins": [
    {
      "type": "flannel",
      "delegate": {
         "hairpinMode": true,
         "isDefaultGateway": true
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    },
    {
       "type": "cilium-cni",
       "enable-debug": {{.Debug | js }},
       "log-file": "{{.LogFile | js }}"
    }
  ]
}
`,
	"portmap": `
{
  "cniVersion": "0.3.1",
  "name": "portmap",
  "plugins": [
    {
       "type": "cilium-cni",
       "enable-debug": {{.Debug | js }},
       "log-file": "{{.LogFile | js }}"
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
}
`,
}

// The CNI plugin config we inject in to the plugins[] array of existing AWS configs
const awsCNIEntry = `
{
	"type": "cilium-cni",
	"enable-debug": {{.Debug | js }},
	"log-file": "{{.LogFile | js }}"
}
`

const cniControllerName = "write-cni-file"

// startCNIConfWriter starts the CNI configuration file manager.
//
// This has two responsibilities:
// - remove any existing non-Cilium CNI configuration files
// - write the Cilium configuration file when ready.
//
// This is done once the daemon has started up, to signify to the
// kubelet that we're ready to handle sandbox creation.
// There are numerous conflicting CNI options, exposed in Helm and
// the cilium-config config map.
//
// This consumes the following config map keys (or equivalent arguments):
// - write-cni-conf-when-ready=PATH -- path to write the CNI config. If blank, don't manage CNI config
// - read-cni-conf -- A "source" CNI file to use, rather than generating one
// - cni-chaining-mode=MODE -- The CNI configuration format to use, e.g. aws-cni, flannel.
// - cni-exlusive -- if true, then remove other existing CNI configurations
// - cni-log-file=PATH -- A file for the CNI plugin to use for logging
// - debug -- Whether or not the CNI plugin binary should be verbose
//
// As well as the following deprecated environment variables:
// - CILIUM_CUSTOM_CNI_CONF -- if true, then don't touch CNI configuration
// - CNI_CONF_NAME -- the filename (NOT full path) to write the CNI configuration to
func (d *Daemon) startCNIConfWriter(opts *option.DaemonConfig, cleaner *daemonCleanup) {
	if opts.WriteCNIConfigurationWhenReady == "" || opts.DryMode {
		return
	}

	// We used to disable CNI generation with this environment variable
	// It's no longer documented, but we need to still support it.
	if os.Getenv("CILIUM_CUSTOM_CNI_CONF") == "true" && opts.ReadCNIConfiguration == "" {
		return
	}

	cniConfDir, _ := cniConfPaths(opts)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warnf("Failed to create watcher: %v", err)
	} else {
		if err := watcher.Add(cniConfDir); err != nil {
			log.Warnf("Failed to watch CNI configuration directory %s: %v", cniConfDir, err)
			watcher = nil
		}
	}

	// Install the CNI file controller
	d.controllers.UpdateController(cniControllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				err := setupCNIConfFile(opts, d.bootstrapCompleted)
				if err != nil {
					log.Printf("Failed to write CNI config file (will retry): %v", err)
				}
				return err
			},
			StopFunc: func(_ context.Context) error {
				if watcher != nil {
					watcher.Close()
				}
				return nil
			},
			Context:                d.ctx,
			ErrorRetryBaseDuration: 10 * time.Second,
		},
	)

	// Watch the CNI directory for changes, re-triggering an update just in case someone
	// wrote a file we're interested in.
	go func() {
		if watcher == nil {
			return
		}
		for {
			select {
			case _, ok := <-watcher.Events:
				if !ok {
					return
				}
				log.Infof("Activity in %s, re-generating CNI configuration", cniConfDir)
				d.controllers.TriggerController(cniControllerName)
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Errorf("Error while watching CNI configuration directory: %v", err)
			case <-d.ctx.Done():
				return
			}
		}
	}()

	cleaner.cleanupFuncs.Add(func() {
		removeCNIConfFile(opts)
	})
}

// setupCNIConfFile tries to render and write the CNI configuration file to disk.
// Returns error on failure.
func setupCNIConfFile(opts *option.DaemonConfig, daemonReady <-chan struct{}) error {
	var contents []byte
	var err error

	// Rename any non-cilium CNI config files.
	// Do this even if the daemon isn't ready; we want to minimize
	// the time that pods might start with the wrong network.
	cleanupOtherCNI(opts)

	// if daemonReady is closed, agent is done initializing and we should write our CNI config file
	select {
	case <-daemonReady:
	default:
		log.Debug("daemon not initialized; skipping CNI file creation")
		return nil
	}

	confDir, filename := cniConfPaths(opts)

	// generate CNI config, either by reading a user-supplied
	// template file or rendering our own.
	if opts.ReadCNIConfiguration != "" {
		contents, err = os.ReadFile(opts.ReadCNIConfiguration)
		if err != nil {
			return fmt.Errorf("failed to read source CNI config file at %s: %w", opts.ReadCNIConfiguration, err)
		}
		log.Infof("Reading CNI configuration file from %s", opts.ReadCNIConfiguration)
	} else {
		contents, err = renderCNIConf(opts, confDir)
		if err != nil {
			return fmt.Errorf("failed to render CNI configuration file: %w", err)
		}
	}

	dest := path.Join(confDir, filename)

	// Check to see if existing file is the same; if so, do nothing
	existingContents, err := os.ReadFile(dest)
	if err == nil && bytes.Equal(existingContents, contents) {
		log.Debugf("Existing CNI configuration file %s unchanged", dest)
	} else {
		if err != nil && !os.IsNotExist(err) {
			log.Debugf("Failed to read existing CNI configuration file %s: %v", dest, err)
		}
		// commit CNI config
		if err := renameio.WriteFile(path.Join(confDir, filename), contents, 0644); err != nil {
			return fmt.Errorf("failed to write CNI configuration file at %s: %w", dest, err)
		}
		log.Infof("Wrote CNI configuration file to %s", dest)
	}

	return nil
}

func removeCNIConfFile(opts *option.DaemonConfig) {
	// Don't touch anything if we're not in charge of CNI configuration, or
	// we didn't ensure the CNI configuration directory was empty.
	// This is because we don't want any existing CNI configurations to "take over"
	// when we remove cilium.
	if opts.WriteCNIConfigurationWhenReady == "" || !opts.CNIExclusive {
		return
	}

	err := os.Remove(opts.WriteCNIConfigurationWhenReady)
	if err != nil {
		log.Errorf("Failed to remove CNI configuration file at %s: %v", opts.WriteCNIConfigurationWhenReady, err)
	}
	log.Infof("Removed CNI configuration file at %s", opts.WriteCNIConfigurationWhenReady)
}

// renderCNIConf renders the CNI configuration file based on the parameters.
// Note: this is somewhat special for AWS, see tryInjectAWSConfig.
func renderCNIConf(opts *option.DaemonConfig, confDir string) (cniConfig []byte, err error) {
	// special case: AWS adjusts existing file rather than creating
	// one from scratch
	if opts.CNIChainingMode == "aws-cni" {
		pluginConfig := renderCNITemplate(awsCNIEntry, opts)
		cniConfig, err = mergeExistingAWSCNIConfig(confDir, pluginConfig)
		if err != nil {
			return nil, err
		}
	} else {
		mode := opts.CNIChainingMode
		if mode == "" {
			mode = "none"
		}
		log.Infof("Generating CNI configuration file with mode %s", mode)
		tmpl := cniConfigs[opts.CNIChainingMode]
		cniConfig = []byte(renderCNITemplate(tmpl, opts))
	}

	if len(cniConfig) == 0 {
		return nil, fmt.Errorf("invalid CNI chaining mode: %s", opts.CNIChainingMode)
	}

	return cniConfig, nil
}

// mergeExistingAWSCNIConfig looks for an existing AWS cni configuration file
// and modifies it to include Cilium. This is because they do something
// "special" for v6-only clusters.
//
// cniDir is the directory in the container to look for AWS CNI config, and
// pluginConfig is the raw json to insert
//
// See PR #18522 for details.
func mergeExistingAWSCNIConfig(confDir string, pluginConfig []byte) ([]byte, error) {
	awsFiles := []string{"10-aws.conflist", "10-aws.conflist.cilium_bak"}
	found, err := findFile(confDir, awsFiles)
	if err != nil {
		return nil, fmt.Errorf("could not find existing AWS CNI config for chaining %w", err)
	}

	contents, err := os.ReadFile(found)
	if err != nil {
		return nil, fmt.Errorf("failed to read existing AWS CNI config %s: %w", found, err)
	}

	// We found the CNI configuration,
	// inject Cilium as the last chained plugin
	out, err := sjson.SetRawBytes(contents, "plugins.-1", pluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to modify existing AWS CNI config at %s: %w", found, err)
	}
	log.Infof("Inserting cilium in to CNI configuration file at %s", found)
	return out, nil
}

// renderCNITemplate applies any cni template replacements
// right now, just sets .Debug and Logfile
func renderCNITemplate(in string, opts *option.DaemonConfig) []byte {
	data := struct {
		Debug   bool
		LogFile string
	}{
		Debug:   opts.Debug,
		LogFile: opts.CNILogFile,
	}

	t := template.Must(template.New("cni").Parse(in))

	out := bytes.Buffer{}
	if err := t.Execute(&out, data); err != nil {
		panic(err) // impossible
	}
	return out.Bytes()
}

// cleanupOldCNI renames any existing CNI configuration files with the suffix
// ".cilium_bak", excepting files in keep
func cleanupOtherCNI(opts *option.DaemonConfig) error {
	if !opts.CNIExclusive || opts.DryMode {
		return nil
	}
	confDir, cniFile := cniConfPaths(opts)
	files, err := os.ReadDir(confDir)
	if err != nil {
		return fmt.Errorf("failed to list CNI conf dir %s: %w", confDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if name == cniFile {
			continue
		}
		if !(strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".conflist") || strings.HasSuffix(name, ".json")) {
			continue
		}

		log.Infof("Renaming non-Cilium CNI configuration file %s to %s.cilium_bak", name, name)
		_ = os.Rename(path.Join(confDir, name), path.Join(confDir, name+".cilium_bak"))
	}
	return nil
}

// findFile looks in basedir for any filenames listed in paths.
// returns the full path to the first one found, or error if none found
func findFile(basedir string, paths []string) (string, error) {
	for _, p := range paths {
		_, err := os.Stat(path.Join(basedir, p))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		} else {
			return path.Join(basedir, p), nil
		}
	}

	return "", os.ErrNotExist
}

func cniConfPaths(opts *option.DaemonConfig) (cniConfDir, cniFile string) {
	// Determine the path to the CNI conf directory
	cniConfDir, cniFile = path.Split(opts.WriteCNIConfigurationWhenReady)

	// we used to document overriding the CNI file with the env var CNI_CONF_NAME
	// this is no longer documented, but we still support it
	if override := os.Getenv("CNI_CONF_NAME"); override != "" {
		cniFile = override
	}
	return
}
