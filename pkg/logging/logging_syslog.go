// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package logging

import (
	"log/slog"
	"log/syslog"
)

const (
	SLevel    = "syslog.level"
	SNetwork  = "syslog.network"
	SAddress  = "syslog.address"
	SSeverity = "syslog.severity"
	SFacility = "syslog.facility"
	STag      = "syslog.tag"
)

var (
	// syslogOpts is the set of supported options for syslog configuration.
	syslogOpts = map[string]bool{
		SLevel:    true,
		SNetwork:  true,
		SAddress:  true,
		SSeverity: true,
		SFacility: true,
		STag:      true,
	}

	// From /usr/include/sys/syslog.h.
	syslogSeverityMap = map[string]syslog.Priority{
		"emerg":   syslog.LOG_EMERG,
		"panic":   syslog.LOG_EMERG,
		"alert":   syslog.LOG_ALERT,
		"crit":    syslog.LOG_CRIT,
		"err":     syslog.LOG_ERR,
		"error":   syslog.LOG_ERR,
		"warn":    syslog.LOG_WARNING,
		"warning": syslog.LOG_WARNING,
		"notice":  syslog.LOG_NOTICE,
		"info":    syslog.LOG_INFO,
		"debug":   syslog.LOG_DEBUG,
	}

	// From /usr/include/sys/syslog.h.
	syslogFacilityMap = map[string]syslog.Priority{
		"kern":     syslog.LOG_KERN,
		"user":     syslog.LOG_USER,
		"mail":     syslog.LOG_MAIL,
		"daemon":   syslog.LOG_DAEMON,
		"auth":     syslog.LOG_AUTH,
		"syslog":   syslog.LOG_SYSLOG,
		"lpr":      syslog.LOG_LPR,
		"news":     syslog.LOG_NEWS,
		"uucp":     syslog.LOG_UUCP,
		"cron":     syslog.LOG_CRON,
		"authpriv": syslog.LOG_AUTHPRIV,
		"ftp":      syslog.LOG_FTP,
		"local0":   syslog.LOG_LOCAL0,
		"local1":   syslog.LOG_LOCAL1,
		"local2":   syslog.LOG_LOCAL2,
		"local3":   syslog.LOG_LOCAL3,
		"local4":   syslog.LOG_LOCAL4,
		"local5":   syslog.LOG_LOCAL5,
		"local6":   syslog.LOG_LOCAL6,
		"local7":   syslog.LOG_LOCAL7,
	}

	// syslogLevelMap maps slog.Level values to syslog.Priority levels.
	syslogLevelMap = map[slog.Level]syslog.Priority{
		LevelPanic:      syslog.LOG_ALERT,
		LevelFatal:      syslog.LOG_CRIT,
		slog.LevelError: syslog.LOG_ERR,
		slog.LevelWarn:  syslog.LOG_WARNING,
		slog.LevelInfo:  syslog.LOG_INFO,
		slog.LevelDebug: syslog.LOG_DEBUG,
	}
)

func mapStringPriorityToSlice(m map[string]syslog.Priority) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

// setupSyslog sets up and configures syslog with the provided options in
// logOpts. If some options are not provided, sensible defaults are used.
func setupSyslog(logOpts LogOptions, tag string, debug bool) error {
	opts := getLogDriverConfig(Syslog, logOpts)
	syslogOptValues := make(map[string][]string)
	syslogOptValues[SSeverity] = mapStringPriorityToSlice(syslogSeverityMap)
	syslogOptValues[SFacility] = mapStringPriorityToSlice(syslogFacilityMap)
	if err := opts.validateOpts(Syslog, syslogOpts, syslogOptValues); err != nil {
		return err
	}
	if stag, ok := opts[STag]; ok {
		tag = stag
	}

	logLevel, ok := opts[SLevel]
	if !ok {
		if debug {
			logLevel = "debug"
		} else {
			logLevel = "info"
		}
	}

	// Validate provided log level.
	level, err := ParseLevel(logLevel)
	if err != nil {
		Fatal(DefaultSlogLogger, err.Error())
	}

	network := ""
	address := ""
	// Inherit severity from log level if syslog.severity is not specified explicitly
	severity := syslogLevelMap[level]
	// Default values for facility if not specified
	facility := syslog.LOG_KERN
	if networkStr, ok := opts[SNetwork]; ok {
		network = networkStr
	}
	if addressStr, ok := opts[SAddress]; ok {
		address = addressStr
	}
	if severityStr, ok := opts[SSeverity]; ok {
		severity = syslogSeverityMap[severityStr]
	}
	if facilityStr, ok := opts[SFacility]; ok {
		facility = syslogFacilityMap[facilityStr]
	}

	// Create syslog hook.
	h, err := NewSyslogHook(network, address, severity|facility, tag, level)
	if err != nil {
		Fatal(DefaultSlogLogger, err.Error())
	}
	AddHandlers(h)

	return nil
}
