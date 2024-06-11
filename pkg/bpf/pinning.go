// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Cilium-specific pinning flags used in bpf C code to request specific pinning
// behaviour from the agent.
const (
	// PinAlwaysReplace matches CILIUM_PIN_REPLACE.
	PinReplace = ebpf.PinType(1 << 4)
)

// consumePinReplace returns the key names of MapSpecs in spec with the
// CILIUM_PIN_REPLACE pinning flag set. Clears the CILIUM_PIN_REPLACE flag.
func consumePinReplace(spec *ebpf.CollectionSpec) []string {
	var toReplace []string
	for key, ms := range spec.Maps {
		if ms.Pinning == PinReplace {
			toReplace = append(toReplace, key)
			ms.Pinning = 0
		}
	}
	return toReplace
}

// incompatibleMaps returns the key names MapSpecs in spec with the
// LIBBPF_PIN_BY_NAME pinning flag that are incompatible with their pinned
// counterparts. Removes the LIBBPF_PIN_BY_NAME flag. opts.Maps.PinPath must be
// specified.
//
// The slice of strings returned contains the keys used in Collection.Maps and
// CollectionSpec.Maps, which can differ from the Map's Name field.
func incompatibleMaps(spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions) ([]string, error) {
	if opts.Maps.PinPath == "" {
		return nil, errors.New("missing opts.Maps.PinPath")
	}

	var incompatible []string
	for key, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinByName {
			continue
		}

		pinPath := path.Join(opts.Maps.PinPath, ms.Name)
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("opening map %s from pin: %w", ms.Name, err)
		}

		if ms.Compatible(m) == nil {
			m.Close()
			continue
		}

		incompatible = append(incompatible, key)
		ms.Pinning = 0
	}

	return incompatible, nil
}

// commitMapPins commits the maps specified in toReplace to bpffs. This is to be
// called after the Collection's programs have been attached to the required
// hooks. Any existing pins are overwritten.
//
// This has two main purposes: replacing pins of incompatible maps that are
// upgraded or downgraded by a different version of the agent, as well as
// replacing pins of maps that should never be reused/repopulated by the loader,
// like tail call maps.
//
// Letting the loader repopulate an existing tail call map will transition the
// program through invalid states. For example, code can be moved from one tail
// call to another, making some instructions execute twice or not at all
// depending on the order the tail calls were inserted.
func commitMapPins(toReplace []string, spec *ebpf.CollectionSpec, coll *ebpf.Collection, opts ebpf.CollectionOptions) error {
	if opts.Maps.PinPath == "" {
		return errors.New("empty Maps.PinPath in CollectionOptions")
	}

	// We need both Map and MapSpec as the pin path is derived from MapSpec.Name,
	// and can be modified before creating the Collection. Maps are often renamed
	// to give them unique bpffs pin paths. MapInfo is/was truncated to 20 chars,
	// so we need the MapSpec.Name.
	for _, key := range toReplace {
		m, ok := coll.Maps[key]
		if !ok {
			return fmt.Errorf("Map %s not found in Collection", key)
		}
		ms, ok := spec.Maps[key]
		if !ok {
			return fmt.Errorf("MapSpec %s not found in CollectionSpec", key)
		}

		if m.IsPinned() {
			return fmt.Errorf("Map %s was already pinned by ebpf-go: LIBBPF_PIN_BY_NAME and CILIUM_PIN_REPLACE are mutually exclusive", ms.Name)
		}

		pinPath := path.Join(opts.Maps.PinPath, ms.Name)
		if err := os.Remove(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing map pin for %s at %s: %w", ms.Name, pinPath, err)
		}
		if err := m.Pin(pinPath); err != nil {
			return fmt.Errorf("pinning map %s to %s: %w", ms.Name, pinPath, err)
		}

		log.Debugf("Replaced map pin %s", pinPath)
	}

	return nil
}
