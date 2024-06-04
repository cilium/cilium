// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/google/renameio/v2"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	checkpointFile = "fqdn-name-manager-selectors.json"

	checkpointController      = "fqdn-selector-checkpointing"
	checkpointTriggerInterval = 10 * time.Second
)

// serializedSelector is the schema of the serialized selectors on disk
type serializedSelector struct {
	Regex    string           `json:"re"`
	Selector api.FQDNSelector `json:"sel"`
}

// setupSelectorCheckpointController returns a new trigger, which when invoked,
// will write all selectors known to the NameManager to disk. This allows Cilium 1.16+
// (which has a new way of managing identities for FQDN selectors) to restore the
// IPCache with selector-based identities and thus allows for a dropless upgrade.
func (n *NameManager) setupSelectorCheckpointController() *trigger.Trigger {
	checkpointPath := filepath.Join(option.Config.StateDir, checkpointFile)

	n.manager.UpdateController(checkpointController, controller.ControllerParams{
		Group: controller.NewGroup("fqdn-name-manager"),
		DoFunc: func(ctx context.Context) error {
			n.Lock()
			selectors := make([]serializedSelector, 0, len(n.allSelectors))
			for selector, re := range n.allSelectors {
				selectors = append(selectors, serializedSelector{
					Regex:    re.String(),
					Selector: selector,
				})
			}
			n.Unlock()

			slices.SortFunc(selectors, func(a, b serializedSelector) int {
				if mn := cmp.Compare(a.Selector.MatchName, b.Selector.MatchName); mn != 0 {
					return mn
				}
				if mp := cmp.Compare(a.Selector.MatchPattern, b.Selector.MatchPattern); mp != 0 {
					return mp
				}
				return cmp.Compare(a.Regex, b.Regex)
			})

			out, err := renameio.NewPendingFile(checkpointPath, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
			if err != nil {
				return fmt.Errorf("failed to prepare checkpoint file: %w", err)
			}
			defer out.Cleanup()

			if err := json.NewEncoder(out).Encode(selectors); err != nil {
				return fmt.Errorf("failed to checkpoint fqdn selectors: %w", err)
			}
			if err := out.CloseAtomicallyReplace(); err != nil {
				return fmt.Errorf("failed to write fqdn selector checkpoint file: %w", err)
			}

			log.WithField("selectors", len(selectors)).Debug("Wrote FQDN selector checkpoint file")
			return nil
		},
	})

	t, _ := trigger.NewTrigger(trigger.Parameters{
		Name:        checkpointController,
		MinInterval: checkpointTriggerInterval,
		TriggerFunc: func(reasons []string) {
			n.manager.TriggerController(checkpointController)
		},
	})

	return t
}

func (n *NameManager) triggerSelectorCheckpoint() {
	if n.checkpointSelectors != nil {
		n.checkpointSelectors.Trigger()
	}
}
