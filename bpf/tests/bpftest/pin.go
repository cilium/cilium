// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpftests

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

func pinCollection(coll *ebpf.Collection, dir string) (err error) {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(dir))
		}
	}()

	for _, kind := range []string{"maps", "programs"} {
		if err := os.Mkdir(filepath.Join(dir, kind), 0700); err != nil {
			return err
		}
	}

	// bpffs rejects dots; hyphens keep ELF sections distinct from C identifiers.
	for name, m := range coll.Maps {
		if err := m.Pin(filepath.Join(dir, "maps", strings.ReplaceAll(name, ".", "-"))); err != nil {
			return fmt.Errorf("pin map %q: %w", name, err)
		}
	}
	for name, prog := range coll.Programs {
		if err := prog.Pin(filepath.Join(dir, "programs", strings.ReplaceAll(name, ".", "-"))); err != nil {
			return fmt.Errorf("pin program %q: %w", name, err)
		}
	}
	return nil
}
