package logutil

import (
	"flag"
)

func init() {
	threshold := flag.Lookup("stderrthreshold")
	if threshold == nil {
		panic("the logging module doesn't specify a stderrthreshold flag")
	}
	const warningLevel = "1"
	if err := threshold.Value.Set(warningLevel); err != nil {
		panic(err)
	}
	threshold.DefValue = warningLevel
}
