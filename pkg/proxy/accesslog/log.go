// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package accesslog

import (
	"encoding/json"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// the agent-level logrus logger
	log = logging.DefaultLogger

	logMutex lock.Mutex
	logger   *lumberjack.Logger
	notifier LogRecordNotifier
	logPath  string
	metadata []string
)

// fields used for structured logging
const (
	FieldType     = "type"
	FieldVerdict  = "verdict"
	FieldCode     = "code"
	FieldMethod   = "method"
	FieldURL      = "url"
	FieldProtocol = "protocol"
	FieldHeader   = "header"
	FieldFilePath = logfields.Path
	FieldMessage  = "message"
)

// fields used for structured logging of Kafka messages
const (
	FieldKafkaAPIKey        = "kafkaApiKey"
	FieldKafkaAPIVersion    = "kafkaApiVersion"
	FieldKafkaCorrelationID = "kafkaCorrelationID"
)

// Called with lock held
func openLogfileLocked(lf string) error {
	logPath = lf
	log.WithField(FieldFilePath, logPath).Debug("Opened access log")

	logger = &lumberjack.Logger{
		Filename:   lf,
		MaxSize:    100, // megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, // disabled by default
	}

	return nil
}

// LogRecordNotifier is the interface to implement LogRecord notifications
type LogRecordNotifier interface {
	// NewProxyLogRecord is called for each new log record
	NewProxyLogRecord(l *LogRecord) error
}

// OpenLogfile opens a file for logging
func OpenLogfile(lf string) error {
	logMutex.Lock()
	defer logMutex.Unlock()

	return openLogfileLocked(lf)
}

// SetNotifier sets the notifier to call for all L7 records
func SetNotifier(n LogRecordNotifier) {
	logMutex.Lock()
	notifier = n
	logMutex.Unlock()
}

// Called with lock held.
func closeLogfileLocked() {
	log.WithField(FieldFilePath, logPath).Debug("Closed access log")
}

// CloseLogfile closes the log file.
func CloseLogfile() {
	logMutex.Lock()
	defer logMutex.Unlock()

	closeLogfileLocked()
}

// SetMetadata sets the metadata to include in each record
func SetMetadata(md []string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	metadata = md
}

// Called with lock held.
func logString(outStr string, retry bool) {
	output := []byte(outStr + "\n")
	_, err := logger.Write(output)
	if err != nil {
		log.WithError(err).WithField(FieldFilePath, logPath).
			Errorf("Error writing to access file")
	}
}

// Log logs a record to the logfile and flushes the buffer
func (l *LogRecord) Log() {
	// Lock while writing access log so we serialize writes as we may have
	// to reopen the logfile and parallel writes could fail because of that
	logMutex.Lock()
	defer logMutex.Unlock()

	l.Metadata = metadata

	if notifier != nil {
		notifier.NewProxyLogRecord(l)
	}

	if logger == nil {
		flowdebug.Log(log.WithField(FieldFilePath, logPath),
			"Skipping writing to access log (logger nil)")
		return
	}

	b, err := json.Marshal(*l)
	if err != nil {
		logString(err.Error(), true)
	} else {
		logString(string(b), true)
	}
}
