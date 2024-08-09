// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cast"
	"golang.org/x/exp/maps"

	k8sConsts "github.com/cilium/cilium/pkg/k8s/constants"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/option/resolver"
)

// sourceValue tracks value source origin.
type sourceValue struct {
	value, source string
}

// String returns a source value for humans.
func (s sourceValue) String() string {
	return fmt.Sprintf("%s[%s]", s.value, s.source)
}

// sourceSettings tracks config settings for a given source.
type sourceSettings map[string]sourceValue

func newSourceSettings(s string, mm map[string]string) sourceSettings {
	ss := make(map[string]sourceValue, len(mm))
	for k, v := range mm {
		ss[k] = sourceValue{value: v, source: s}
	}

	return ss
}

func (mm sourceSettings) overlay(desired sourceSettings) sourceSettings {
	for k, v := range desired {
		if _, ok := mm[k]; ok {
			mm[k] = v
		}
	}

	return mm
}

// computeDeltas compute deltas between desired config settings and agent settings.
func (mm sourceSettings) computeDeltas(settings map[string]string) []string {
	var dd []string
	for k, v := range mm {
		if sv, ok := settings[k]; ok {
			if v.value != sv {
				dd = append(dd, fmt.Sprintf("Mismatch for key [%s::%s]: expecting %q but got %q", v.source, k, v.value, sv))
			}
		} else {
			dd = append(dd, fmt.Sprintf("No entry found for key: [%s::%s]", v.source, k))
		}
	}
	slices.Sort(dd)

	return dd
}

// computeSettingsCheckSum computes config settings checksum.
func (mm sourceSettings) computeCheckSum() string {
	kk := maps.Keys[sourceSettings](mm)
	slices.Sort(kk)

	ss := make([]string, 0, len(mm))
	for _, k := range kk {
		ss = append(ss, k+":"+mm[k].String())
	}

	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(ss, ","))))
}

// settingsDelta tracks deltas between agent settings and cilium-config configmap.
type settingsDelta struct {
	// deltas tracks deltas between ConfigMap and agent settings.
	deltas []string

	// md5 tracks configmap version
	md5 string
}

func (s settingsDelta) hasDeltas() bool {
	return len(s.deltas) != 0
}

func (s settingsDelta) deltaCount() int {
	return len(s.deltas)
}

// newSettingsDelta computes deltas between daemon settings and cilium config map.
// If per node config is available, overlay the overrides prior to computing the deltas.
func newSettingsDelta(ctx context.Context, d *Daemon) (settingsDelta, error) {
	var (
		sd   settingsDelta
		node = os.Getenv(k8sConsts.EnvNodeNameSpec)
	)
	cmCfg, _, err := resolver.ReadConfigSource(ctx, d.clientset, node, resolver.ConfigSource{
		Kind:      resolver.KindConfigMap,
		Namespace: option.Config.K8sNamespace,
		Name:      "cilium-config",
	})
	if err != nil {
		return sd, err
	}
	cmSettings := newSourceSettings(resolver.KindConfigMap, cmCfg)
	noCfg, _, err := resolver.ReadConfigSource(ctx, d.clientset, node, resolver.ConfigSource{
		Kind:      resolver.KindNodeConfig,
		Namespace: option.Config.K8sNamespace,
	})
	if err != nil {
		log.Debugf("cilium node configuration load failed: %s", err)
	}
	cmSettings = cmSettings.overlay(
		newSourceSettings(resolver.KindNodeConfig, noCfg),
	)

	diskCfg, err := option.ReadDirConfig(option.Config.ConfigDir)
	if err != nil {
		return sd, fmt.Errorf("unable to read from config dir %q: %w", option.Config.ConfigDir, err)
	}
	settings := make(map[string]string, len(diskCfg))
	for k, v := range diskCfg {
		settings[k] = cast.ToString(v)
	}
	sd.deltas = cmSettings.computeDeltas(settings)
	sd.md5 = cmSettings.computeCheckSum()

	return sd, nil
}
