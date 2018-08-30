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

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/go-openapi/runtime/middleware"
)

type getMapName struct {
	daemon *Daemon
}

func NewGetMapNameHandler(d *Daemon) restapi.GetMapNameHandler {
	return &getMapName{daemon: d}
}

func (h *getMapName) Handle(params restapi.GetMapNameParams) middleware.Responder {
	m := bpf.GetMap(params.Name)
	if m == nil {
		return restapi.NewGetMapNameNotFound()
	}

	return restapi.NewGetMapNameOK().WithPayload(m.GetModel())
}

type getMap struct {
	daemon *Daemon
}

func NewGetMapHandler(d *Daemon) restapi.GetMapHandler {
	return &getMap{daemon: d}
}

func (h *getMap) Handle(params restapi.GetMapParams) middleware.Responder {
	mapList := &models.BPFMapList{
		Maps: bpf.GetOpenMaps(),
	}

	return restapi.NewGetMapOK().WithPayload(mapList)
}

func (d *Daemon) validateExistingMaps() error {
	walker := func(path string, _ os.FileInfo, _ error) error {
		return mapValidateWalker(path)
	}

	return filepath.Walk(bpf.MapPrefixPath(), walker)
}

func (d *Daemon) collectStaleMapGarbage() {
	if option.Config.DryMode {
		return
	}
	walker := func(path string, _ os.FileInfo, _ error) error {
		return d.staleMapWalker(path)
	}

	if err := filepath.Walk(bpf.MapPrefixPath(), walker); err != nil {
		log.WithError(err).Warn("Error while scanning for stale maps")
	}
}

func (d *Daemon) removeStaleMap(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

func (d *Daemon) removeStaleIDFromPolicyMap(id uint32) {
	gpm, err := policymap.OpenGlobalMap(bpf.MapPath(endpoint.PolicyGlobalMapName))
	if err == nil {
		gpm.Delete(id, policymap.AllPorts, u8proto.All, policymap.Ingress)
		gpm.Delete(id, policymap.AllPorts, u8proto.All, policymap.Egress)
		gpm.Close()
	}
}

func (d *Daemon) checkStaleMap(path string, filename string, id string) {
	if tmp, err := strconv.ParseUint(id, 0, 16); err == nil {
		if ep := endpointmanager.LookupCiliumID(uint16(tmp)); ep == nil {
			d.removeStaleIDFromPolicyMap(uint32(tmp))
			d.removeStaleMap(path)
		}
	}
}

func (d *Daemon) checkStaleGlobalMap(path string, filename string) {
	globalCTinUse := endpointmanager.HasGlobalCT()

	if !globalCTinUse &&
		(filename == ctmap.MapName6Global ||
			filename == ctmap.MapName4Global) {
		d.removeStaleMap(path)
	}
}

func (d *Daemon) staleMapWalker(path string) error {
	filename := filepath.Base(path)

	mapPrefix := []string{
		policymap.MapName,
		ctmap.MapName6,
		ctmap.MapName4,
		endpoint.CallsMapName,
	}

	d.checkStaleGlobalMap(path, filename)

	for _, m := range mapPrefix {
		if strings.HasPrefix(filename, m) {
			if id := strings.TrimPrefix(filename, m); id != filename {
				d.checkStaleMap(path, filename, id)
			}
		}
	}

	return nil
}

func mapValidateWalker(path string) error {
	prefixToValidator := map[string]bpf.MapValidator{
		policymap.MapName: policymap.Validate,
	}

	filename := filepath.Base(path)
	for m, validate := range prefixToValidator {
		if strings.HasPrefix(filename, m) {
			valid, err := validate(path)
			switch {
			case err != nil:
				return err
			case !valid:
				log.WithField(logfields.Path, filename).Info("Outdated non-persistent BPF map found, removing...")

				if err := os.Remove(path); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
