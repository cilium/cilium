//go:build solaris
// +build solaris

package load

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

func Avg() (*AvgStat, error) {
	return AvgWithContext(context.Background())
}

func AvgWithContext(ctx context.Context) (*AvgStat, error) {
	kstat, err := exec.LookPath("kstat")
	if err != nil {
		return nil, err
	}

	out, err := invoke.CommandWithContext(ctx, kstat, "-p", "unix:0:system_misc:avenrun_*")
	if err != nil {
		return nil, err
	}

	avg := &AvgStat{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		flds := strings.Fields(scanner.Text())
		if len(flds) < 2 {
			continue
		}
		var tgt *float64
		switch {
		case strings.HasSuffix(flds[0], ":avenrun_1min"):
			tgt = &avg.Load1
		case strings.HasSuffix(flds[0], ":avenrun_5min"):
			tgt = &avg.Load5
		case strings.HasSuffix(flds[0], ":avenrun_15min"):
			tgt = &avg.Load15
		default:
			continue
		}
		v, err := strconv.ParseInt(flds[1], 10, 64)
		if err != nil {
			return nil, err
		}
		*tgt = float64(v) / (1 << 8)
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return avg, nil
}

func Misc() (*MiscStat, error) {
	return MiscWithContext(context.Background())
}

func MiscWithContext(ctx context.Context) (*MiscStat, error) {
	bin, err := exec.LookPath("ps")
	if err != nil {
		return nil, err
	}
	out, err := invoke.CommandWithContext(ctx, bin, "-efo", "s")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")

	ret := MiscStat{}
	for _, l := range lines {
		if l == "O" {
			ret.ProcsRunning++
		}
	}

	return &ret, nil
}
