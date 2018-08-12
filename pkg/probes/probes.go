// Copyright 2018 Authors of Cilium
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

package probes

import (
	"os"
	"sync"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/cilium/pkg/probes/api"
	_ "github.com/cilium/cilium/pkg/probes/connect"
)

var (
	initOnce sync.Once
	log      = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
)

const (
	kprobeEventsFile = "/sys/kernel/debug/tracing/kprobe_events"
)

func unloadAllKprobes() {
	f, err := os.OpenFile(kprobeEventsFile, os.O_WRONLY, 0644)
	if err != nil {
		log.WithError(err).Errorf("Unable to open %s", kprobeEventsFile)
	} else {
		_, err := f.Write([]byte{'\n'})
		if err != nil {
			log.WithError(err).Errorf("Unable to write to file %s", kprobeEventsFile)
		} else {
			log.Info("Unloaded all existing kprobes")
		}
		f.Close()
	}
}

// Init loads and attaches all probes that were previously registered. Once
// Init() is called, it does not make sense to call Register()
func Init() {
	initOnce.Do(func() {
		unloadAllKprobes()
		api.Init()
	})
}

// Close unloads and detaches all probes
func Close() {
	api.Close()
}
