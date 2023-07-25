// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package timestamp

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// The BPF CT implementation stores jiffies right-shifted by this value. Must
	// correspond to BPF_MONO_SCALER in the datapath.
	bpfMonoScaler = 8
)

// Get current clocksource - to be used in the agent context.
func GetClockSourceFromOptions() *models.ClockSource {
	clockSource := &models.ClockSource{Mode: models.ClockSourceModeKtime}
	if option.Config.ClockSource == option.ClockSourceJiffies {
		clockSource.Mode = models.ClockSourceModeJiffies
		clockSource.Hertz = int64(option.Config.KernelHz)
	}
	return clockSource
}

// Connect to the agent via API and get its current clocksource.
func GetClockSourceFromAgent(svc daemon.ClientService) (*models.ClockSource, error) {
	params := daemon.NewGetHealthzParamsWithTimeout(5 * time.Second)
	brief := false
	params.SetBrief(&brief)
	resp, err := svc.GetHealthz(params)
	if err != nil {
		return nil, err
	}

	if resp.Payload.ClockSource == nil {
		return nil, fmt.Errorf("could not determine clocksource")
	}

	return resp.Payload.ClockSource, nil
}

// Returns current time in units that are used for timestamps in CT and NAT
// maps (seconds for ClockSourceModeKtime and scaled jiffies for
// ClockSourceModeJiffies).
func GetCTCurTime(clockSource *models.ClockSource) (uint64, error) {
	switch clockSource.Mode {
	case models.ClockSourceModeKtime:
		t, err := bpf.GetMtime()
		if err != nil {
			return 0, err
		}
		return t / 1000000000, nil
	case models.ClockSourceModeJiffies:
		j, err := probes.Jiffies()
		if err != nil {
			return 0, err
		}
		return j >> bpfMonoScaler, nil
	default:
		return 0, fmt.Errorf("invalid clocksource: %s", clockSource.Mode)
	}
}

type TimestampConverter func(timestamp uint64) uint64

// Returns a function that converts a CT timestamp from clocksource units into
// seconds.
func NewCTTimeToSecConverter(clockSource *models.ClockSource) (TimestampConverter, error) {
	if clockSource == nil {
		return nil, fmt.Errorf("clockSource is nil")
	}
	switch clockSource.Mode {
	case models.ClockSourceModeKtime:
		converter := func(timestamp uint64) uint64 {
			return timestamp
		}
		return converter, nil
	case models.ClockSourceModeJiffies:
		hertz := clockSource.Hertz
		if hertz == 0 {
			return nil, fmt.Errorf("invalid clock Hertz value (0)")
		}
		converter := func(timestamp uint64) uint64 {
			return (timestamp << bpfMonoScaler) / uint64(hertz)
		}
		return converter, nil
	default:
		return nil, fmt.Errorf("invalid clocksource: %s", clockSource.Mode)
	}
}
