// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// cleanTCGlobalsOnStart removes all pins under <bpffs>/tc/globals before the
// loader attaches any program, when the clean-tc-bpf-state option is enabled.
//
// Rationale (see #44194, #42573): tc/tcx links and maps pinned under tc/globals
// survive agent restarts and are reused by the restore path (upsertTCXProgram
// -> updateTCX, and the endpoint restore path). When the pinned state has gone
// stale -- observed after agent restarts combined with heavy endpoint churn --
// reusing it can leave the host<->pod datapath silently blackholing traffic.
// Removing the pins forces a clean rebuild of all tc/tcx attachments and maps
// at the cost of a full datapath regeneration on startup.
//
// Unlike the existing clean-cilium-bpf-state init-container hook (which runs
// post-uninstall-cleanup and wipes all BPF state), this only affects the tc
// datapath pins: global maps pinned under <bpffs>/cilium (identities, etc.)
// are preserved, avoiding a full identity churn on restart.
func cleanTCGlobalsOnStart(logger *slog.Logger) {
	if !option.Config.CleanTCBPFState {
		return
	}

	removed, err := removePinsInDir(bpf.TCGlobalsPath())
	if err != nil {
		logger.Warn("clean-tc-bpf-state: failed to list pins, continuing with existing state",
			logfields.Error, err)
		return
	}

	logger.Info("clean-tc-bpf-state: removed pinned tc objects, datapath will be rebuilt from scratch",
		"count", removed,
	)
}

// removePinsInDir removes all entries of dir and returns the number of
// successful removals. A missing dir is not an error; individual removal
// failures are skipped so one stuck pin cannot block the rest of the cleanup.
func removePinsInDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	removed := 0
	for _, e := range entries {
		if err := bpf.Remove(filepath.Join(dir, e.Name())); err != nil {
			continue
		}
		removed++
	}
	return removed, nil
}
