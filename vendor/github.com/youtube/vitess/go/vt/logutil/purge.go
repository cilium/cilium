package logutil

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var (
	keepLogs          = flag.Duration("keep_logs", 0*time.Second, "keep logs for this long (zero to keep forever)")
	purgeLogsInterval = flag.Duration("purge_logs_interval", 1*time.Hour, "how often try to remove old logs")
)

// parse parses a file name (as used by glog) and returns its process
// name and timestamp.
func parseTimestamp(filename string) (timestamp time.Time, err error) {
	parts := strings.Split(filepath.Base(filename), ".")
	if len(parts) < 6 {
		return time.Time{}, fmt.Errorf("malformed logfile name: %v", filename)
	}
	return time.ParseInLocation("20060102-150405", parts[len(parts)-2], time.Now().Location())

}

var levels = []string{"INFO", "ERROR", "WARNING", "FATAL"}

// purgeLogsOnce removes logfiles for program for dir, if their age
// relative to now is greater than keep.
func purgeLogsOnce(now time.Time, dir, program string, keep time.Duration) {
	current := make(map[string]bool)
	for _, level := range levels {
		c, err := os.Readlink(path.Join(dir, fmt.Sprintf("%s.%s", program, level)))
		if err != nil {
			continue
		}
		current[c] = true
	}

	files, err := filepath.Glob(path.Join(dir, fmt.Sprintf("%s.*", program)))
	if err != nil {
		return
	}
	for _, file := range files {
		if current[file] {
			continue
		}
		created, err := parseTimestamp(file)
		if err != nil {
			continue
		}
		if now.Sub(created) > keep {
			os.Remove(file)
		}
	}
}

// PurgeLogs removes any log files that were started more than
// keepLogs ago and that aren't the current log.
func PurgeLogs() {
	f := flag.Lookup("log_dir")
	if f == nil {
		panic("the logging module doesn't specify a log_dir flag")
	}

	if *keepLogs == 0*time.Second {
		return
	}
	logDir := f.Value.String()
	program := filepath.Base(os.Args[0])

	timer := time.NewTimer(*purgeLogsInterval)
	for range timer.C {
		purgeLogsOnce(time.Now(), logDir, program, *keepLogs)
	}
}
