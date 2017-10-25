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
	"bufio"
	"encoding/json"
	"os"

	"github.com/cilium/cilium/pkg/lock"

	log "github.com/sirupsen/logrus"
)

var (
	logMutex lock.Mutex
	logFile  *os.File
	logBuf   *bufio.Writer
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
	FieldFilePath = "file-path"
)

// OpenLogfile opens a file for logging
func OpenLogfile(lf string) error {
	var err error

	if logFile, err = os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
		return err
	}

	logPath = lf
	log.WithField(FieldFilePath, logPath).Debug("Opened access log")

	logBuf = bufio.NewWriter(logFile)
	return nil
}

// CloseLogfile closes the logfile
func CloseLogfile() {
	log.WithField(FieldFilePath, logPath).Debug("Closed access log")

	logBuf.Flush()
	logFile.Close()
}

// SetMetadata sets the metadata to include in each record
func SetMetadata(md []string) {
	metadata = md
}

func logString(outStr string, retry bool) {
	_, err := logBuf.WriteString(outStr + "\n")
	if err != nil {
		if retry {
			log.WithError(err).WithField(FieldFilePath, logPath).Warn("Error encountered while writing to access log, retrying once...")

			CloseLogfile()
			OpenLogfile(logPath)

			// retry once
			logString(outStr, false)
		}
	}
}

// Log logs a record to the logfile and flushes the buffer
func Log(l *LogRecord, typ FlowType, verdict FlowVerdict, code int) {
	// Lock while writing access log so we serialize writes as we may have
	// to reopen the logfile and parallel writes could fail because of that
	logMutex.Lock()
	defer logMutex.Unlock()

	l.Type = typ
	l.Verdict = verdict
	l.Metadata = metadata

	l.HTTP = &LogRecordHTTP{
		Code:     code,
		Method:   l.Request.Method,
		URL:      l.Request.URL,
		Protocol: l.Request.Proto,
		Headers:  l.Request.Header,
	}

	log.WithFields(log.Fields{
		FieldType:     typ,
		FieldVerdict:  verdict,
		FieldCode:     code,
		FieldMethod:   l.Request.Method,
		FieldURL:      l.Request.URL,
		FieldProtocol: l.Request.Proto,
		FieldHeader:   l.Request.Header,
		FieldFilePath: logPath,
	}).Debug("Logging L7 flow record")

	if logBuf == nil {
		log.WithField(FieldFilePath, logPath).Debug("Skipping writing to access log (write buffer nil)")
		return
	}

	b, err := json.Marshal(*l)
	if err != nil {
		logString(err.Error(), true)
	} else {
		logString(string(b), true)
	}

	if err := logBuf.Flush(); err != nil {
		log.WithError(err).WithField(FieldFilePath, logPath).Warn("Error encountered while flushing to access log")
	}
}
