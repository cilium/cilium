// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/option"

	"github.com/containernetworking/cni/libcni"
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

// startCNIConfWriter writes the CNI configuration file to disk.
// This is done once the daemon has started up, to signify to the
// kubelet that we're ready to handle sandbox creation.
// There are numerous, conflicting CNI options, exposed in Helm and
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
	if opts.WriteCNIConfigurationWhenReady == "" {
		return
	}

	// We used to disable CNI generation with this environment variable
	// It's no longer documented, but we need to still support it.
	// If CILIUM_CUSTOM_CNI_CONF == true, we want that cni-install.sh will not generate the 05-cilium.conf or 05-cilium.conflist
	// But we want cilium-agent can install cni according to opts.ReadCNIConfiguration
	if os.Getenv("CILIUM_CUSTOM_CNI_CONF") == "true" && opts.ReadCNIConfiguration == "" {
		return
	}

	d.controllers.UpdateController(cniControllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				err := installCNIConfFile(opts)
				if err != nil {
					log.Printf("Failed to write CNI config file (will retry): %v", err)
				}
				return err
			},
			Context:                d.ctx,
			ErrorRetryBaseDuration: 10 * time.Second,
		},
	)

	cleaner.cleanupFuncs.Add(func() {
		removeCNIConfFile(opts)
	})
}

// installCNIConfFile tries to render and write the CNI configuration file to disk.
// Returns error on failure.
func installCNIConfFile(opts *option.DaemonConfig) error {
	// Determine the path to the CNI conf directory
	confDir, filename := path.Split(opts.WriteCNIConfigurationWhenReady)

	// we used to document overriding the CNI file with the env var CNI_CONF_NAME
	// this is no longer documented, but we still support it
	if override := os.Getenv("CNI_CONF_NAME"); override != "" {
		filename = override
	}

	var contents []byte
	var err error
	originalConfFile := ""

	// generate CNI config, either by reading a user-supplied
	// template file or rendering our own.
	if opts.ReadCNIConfiguration != "" {
		originalConfContents := make([]byte, 0)
		contents, err = os.ReadFile(opts.ReadCNIConfiguration)
		if err != nil {
			return fmt.Errorf("unable to read CNI configuration file %s: %s", opts.ReadCNIConfiguration, err)
		}
		log.Infof("Reading CNI configuration file from %s", opts.ReadCNIConfiguration)
		if opts.WriteCNIConfigurationChainingMode {
			if !strings.HasSuffix(opts.WriteCNIConfigurationWhenReady, ".conflist") {
				return fmt.Errorf("the CNI configuration file %s should be suffixed with .conflist when %v is true", opts.WriteCNIConfigurationWhenReady, opts.WriteCNIConfigurationChainingMode)
			}
			readCniConfContents, err := getCNINetworkListFromFile(opts.ReadCNIConfiguration)
			if err != nil {
				return fmt.Errorf("failed to read the CNI configuration from %s: %s", opts.ReadCNIConfiguration, err.Error())
			}
			if opts.DefaultCNIConfiguration != "" && exists(opts.DefaultCNIConfiguration) {
				// opts.DefaultCNIConfiguration exists
				originalConfFile = opts.DefaultCNIConfiguration
				originalConfContents, err = getCNINetworkListFromFile(opts.DefaultCNIConfiguration)
				if err != nil {
					return fmt.Errorf("unable to read CNI configurations from the file %s", opts.DefaultCNIConfiguration)
				}
			} else if exists(opts.WriteCNIConfigurationWhenReady) {
				// opts.DefaultCNIConfiguration doesn't exist and opts.WriteCNIConfigurationWhenReady exists
				// opts.DefaultCNIConfiguration is empty and opts.WriteCNIConfigurationWhenReady exists
				originalConfFile = opts.WriteCNIConfigurationWhenReady
				originalConfContents, err = getCNINetworkListFromFile(opts.WriteCNIConfigurationWhenReady)
				if err != nil {
					return fmt.Errorf("unable to read the CNI configurations from %s: %s", opts.WriteCNIConfigurationWhenReady, err.Error())
				}
			} else if opts.DefaultCNIConfiguration == "" {
				// opts.DefaultCNIConfiguration is empty and opts.WriteCNIConfigurationWhenReady doesn't exist
				// read the default CNI configuration
				cniPath := filepath.Dir(opts.WriteCNIConfigurationWhenReady)
				log.Infof("The default CNI configuration file is not specified, read the default CNI configuration from %s", cniPath)
				originalConfFile, originalConfContents, err = getDefaultCNINetworkList(cniPath)
				if err != nil {
					log.Warnf("unable to read the original CNI configurations files under %s: %s. Will write the contents of %s directly into %s", cniPath, err.Error(), opts.ReadCNIConfiguration, opts.WriteCNIConfigurationWhenReady)
				}
			}

			if originalConfContents != nil && len(originalConfContents) != 0 {
				// Insert the opts.ReadCNIConfiguration into the original CNI conf file found out above
				log.Infof("Insert the configurations %s into %s and write it into the file %s", opts.ReadCNIConfiguration, originalConfFile, opts.WriteCNIConfigurationWhenReady)
				contents, err = insertConfList(opts.CNIChainingMode, originalConfContents, readCniConfContents)
				if err != nil {
					return fmt.Errorf("unable to combine CNI configuraion %s with %s: %s", opts.ReadCNIConfiguration, originalConfFile, err.Error())
				}
			} else {
				// write opts.ReadCNIConfiguration directly into opts.WriteCNIConfigurationWhenReady
				contents, err = marshalCNIConfigFromBytes(opts.CNIChainingMode, readCniConfContents)
				if err != nil {
					return fmt.Errorf("unable to mashal %s to chained CNI configuration format: %s", opts.ReadCNIConfiguration, err.Error())
				}
			}
		}
	} else {
		contents, err = renderCNIConf(opts, confDir)
		if err != nil {
			return fmt.Errorf("failed to render CNI configuration file: %w", err)
		}
	}

	// commit CNI config
	if err := renameio.WriteFile(path.Join(confDir, filename), contents, 0644); err != nil {
		return fmt.Errorf("failed to write CNI configuration file at %s: %w", opts.WriteCNIConfigurationWhenReady, err)
	}
	log.Infof("Wrote CNI configuration file to %s", opts.WriteCNIConfigurationWhenReady)

	// Remove the original CNI Configuration file
	if originalConfFile != "" && originalConfFile != opts.WriteCNIConfigurationWhenReady {
		log.Infof("Rename CNI configuration file %s to %s", originalConfFile, originalConfFile+".cilium_bak")
		err = os.Rename(originalConfFile, originalConfFile+".cilium_bak")
		if err != nil {
			return fmt.Errorf("unable to rename the original CNI configurations file %s: %s", originalConfFile, err.Error())
		}
	}
	// Remove the old non-conflist cilium file
	if filename != "05-cilium.conf" {
		_ = os.Remove(path.Join(confDir, "05-cilium.conf"))
	}
	// Rename any non-cilium CNI config files.
	if opts.CNIExclusive {
		cleanupOtherCNI(confDir, filename)
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
func cleanupOtherCNI(confDir, keep string) error {
	files, err := os.ReadDir(confDir)
	if err != nil {
		return fmt.Errorf("failed to list CNI conf dir %s: %w", confDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if name == keep {
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

// Get the default CNI configuration under some directory
func getDefaultCNINetworkList(confDir string) (string, []byte, error) {
	files, err := libcni.ConfFiles(confDir, []string{".conf", ".conflist"})
	switch {
	case err != nil:
		return "", nil, err
	case len(files) == 0:
		return "", nil, fmt.Errorf("no networks found in %s", confDir)
	}

	sort.Strings(files)
	for _, confFile := range files {
		confList, err := getCNINetworkListFromFile(confFile)
		if err != nil {
			continue
		}
		return confFile, confList, nil
	}

	return "", nil, fmt.Errorf("no valid networks found in %s", confDir)
}

// Get the CNI network list from the file.
// Try to load CNI network list assuming that it is a chained CNI conf file
// If it is failed, try to load CNI network list assuming it is a single CNI conf file
func getCNINetworkListFromFile(name string) ([]byte, error) {
	var confList *libcni.NetworkConfigList
	var err error

	confList, err = libcni.ConfListFromFile(name)
	if err == nil {
		if len(confList.Plugins) == 0 {
			log.Warnf("CNI config list %s has no networks, skipping", confList.Name)
			return nil, err
		}
		return confList.Bytes, nil
	}

	log.Warnf("Failed to loading CNI config list from the file %s: %v. Try to load CNI config.", name, err)
	conf, err := libcni.ConfFromFile(name)
	if err != nil {
		log.Warnf("Error loading CNI config file %s: %v", name, err)
		return nil, err
	}
	// Ensure the config has a "type" so we know what plugin to run.
	// Also catches the case where somebody put a conflist into a conf file.
	if conf.Network.Type == "" {
		log.Warnf("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", name)
		return nil, err
	}

	confList, err = libcni.ConfListFromConf(conf)
	if err != nil {
		log.Warnf("Error converting CNI config file %s to list: %v", name, err)
		return nil, err
	}

	if len(confList.Plugins) == 0 {
		log.Warnf("CNI config list %s has no networks, skipping", confList.Name)
		return nil, err
	}

	return confList.Bytes, nil
}

// Append the new CNI configuration into the original CNI configuration
func insertConfList(cniChainMode string, original []byte, inserted []byte) ([]byte, error) {
	var originalMap map[string]interface{}
	err := json.Unmarshal(original, &originalMap)
	if err != nil {
		return nil, fmt.Errorf("error loading existing CNI config (JSON error): %v", err)
	}

	var insertedMap map[string]interface{}
	err = json.Unmarshal(inserted, &insertedMap)
	if err != nil {
		return nil, fmt.Errorf("error loading inserted CNI config (JSON error): %v", err)
	}

	newMap := make(map[string]interface{}, 0)
	newMap["name"] = cniChainMode

	if insertedCniVersion, ok := insertedMap["cniVersion"]; ok {
		newMap["cniVersion"] = insertedCniVersion
	} else {
		if existingCniVersion, ok := originalMap["cniVersion"]; ok {
			newMap["cniVersion"] = existingCniVersion
		} else {
			newMap["cniVersion"] = "0.3.1"
		}
	}

	delete(insertedMap, "cniVersion")
	delete(originalMap, "cniVersion")

	originalPlugins, err := getPluginsFromCNIConfigMap(originalMap)
	if err != nil {
		return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
	}

	insertedPlugins, err := getPluginsFromCNIConfigMap(insertedMap)
	if err != nil {
		return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
	}

	for _, insertedPlugin := range insertedPlugins {
		iPlugin, err := getPlugin(insertedPlugin)
		if err != nil {
			return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
		}
		for i, originalPlugin := range originalPlugins {
			oPlugin, err := getPlugin(originalPlugin)
			delete(originalPlugins[i].(map[string]interface{}), "cniVersion")
			if err != nil {
				return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
			}
			if oPlugin["type"] == iPlugin["type"] {
				originalPlugins = append(originalPlugins[:i], originalPlugins[i+1:]...)
				break
			}
		}
		delete(iPlugin, "cniVersion")
		originalPlugins = append(originalPlugins, iPlugin)
	}
	newMap["plugins"] = originalPlugins
	return marshalCNIConfig(newMap)
}

// Get the plugins form CNI config map
func getPluginsFromCNIConfigMap(cniConfigMap map[string]interface{}) ([]interface{}, error) {
	var plugins []interface{}
	var err error
	if _, ok := cniConfigMap["type"]; ok {
		// Assume it is a regular network conf file
		plugins = []interface{}{cniConfigMap}
	} else {
		plugins, err = getPlugins(cniConfigMap)
		if err != nil {
			return nil, fmt.Errorf("error loading CNI config plugins from the existing file: %v", err)
		}
	}
	return plugins, nil
}

// Given the raw plugin interface, return the plugin asserted as a map[string]interface{}
func getPlugin(rawPlugin interface{}) (map[string]interface{}, error) {
	plugin, ok := rawPlugin.(map[string]interface{})
	if !ok {
		err := fmt.Errorf("error reading plugin from CNI config plugin list")
		return plugin, err
	}
	return plugin, nil
}

// Given an unmarshalled CNI config JSON map, return the plugin list asserted as a []interface{}
func getPlugins(cniConfigMap map[string]interface{}) ([]interface{}, error) {
	plugins, ok := cniConfigMap["plugins"].([]interface{})
	if !ok {
		err := fmt.Errorf("error reading plugin list from CNI config")
		return plugins, err
	}
	return plugins, nil
}

// Marshal the CNI config map and append a new line
func marshalCNIConfigFromBytes(cniChainMode string, cniConfigBytes []byte) ([]byte, error) {
	var cniMap map[string]interface{}
	err := json.Unmarshal(cniConfigBytes, &cniMap)
	if err != nil {
		return nil, err
	}
	cniMap["name"] = cniChainMode
	plugins, err := getPluginsFromCNIConfigMap(cniMap)
	if err != nil {
		return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
	}

	newPlugins := make([]interface{}, 0)
	for _, plugin := range plugins {
		iPlugin, err := getPlugin(plugin)
		if err != nil {
			return nil, fmt.Errorf("failed to get the plugin: %s", err.Error())
		}
		delete(iPlugin, "cniVersion")
		newPlugins = append(newPlugins, iPlugin)
	}
	cniMap["plugins"] = newPlugins
	return marshalCNIConfig(cniMap)
}

// Marshal the CNI config map and append a new line
func marshalCNIConfig(cniConfigMap map[string]interface{}) ([]byte, error) {
	cniConfig, err := json.MarshalIndent(cniConfigMap, "", "  ")
	if err != nil {
		return nil, err
	}
	cniConfig = append(cniConfig, "\n"...)
	return cniConfig, nil
}

// Check whether the file exists
func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
