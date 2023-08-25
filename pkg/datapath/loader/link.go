// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"

	"github.com/cilium/cilium/pkg/option"
)

func SetXDPMode(mode string) error {
	switch mode {
	case option.XDPModeNative:
		if option.Config.XDPMode == option.XDPModeLinkNone ||
			option.Config.XDPMode == option.XDPModeLinkDriver {
			option.Config.XDPMode = option.XDPModeLinkDriver
		} else {
			return fmt.Errorf("XDP Mode conflict: current mode is %s, trying to set conflicting %s",
				option.Config.XDPMode, option.XDPModeLinkDriver)
		}
	case option.XDPModeGeneric:
		if option.Config.XDPMode == option.XDPModeLinkNone ||
			option.Config.XDPMode == option.XDPModeLinkGeneric {
			option.Config.XDPMode = option.XDPModeLinkGeneric
		} else {
			return fmt.Errorf("XDP Mode conflict: current mode is %s, trying to set conflicting %s",
				option.Config.XDPMode, option.XDPModeLinkGeneric)
		}
	case option.XDPModeDisabled:
		break
	}
	return nil
}
