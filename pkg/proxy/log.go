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

package proxy

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"

	log "github.com/Sirupsen/logrus"
)

var (
	logMutex sync.Mutex
	logFile  *os.File
	logBuf   *bufio.Writer
	logPath  string
	metadata []string
)

// fields used for logging
const (
	fieldType     = "type"
	fieldVerdict  = "verdict"
	fieldCode     = "code"
	fieldMethod   = "method"
	fieldURL      = "url"
	fieldProtocol = "protocol"
	fieldHeader   = "header"
	fieldPath     = "file-path"
)

// OpenLogfile opens a file for logging
func OpenLogfile(lf string) error {
	var err error

	if logFile, err = os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
		return err
	}

	logPath = lf
	log.WithFields(log.Fields{
		fieldPath: logPath,
	}).Debug("Opened access log")

	logBuf = bufio.NewWriter(logFile)
	return nil
}

// CloseLogfile closes the logfile
func CloseLogfile() {
	log.WithFields(log.Fields{
		fieldPath: logPath,
	}).Debug("Closed access log")

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
			log.WithFields(log.Fields{
				fieldPath: logPath,
			}).WithError(err).Warning("Error encountered while writing to access log, retrying once...")

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
		Method:   l.request.Method,
		URL:      l.request.URL,
		Protocol: l.request.Proto,
		Header:   l.request.Header,
	}

	log.WithFields(log.Fields{
		fieldType:     typ,
		fieldVerdict:  verdict,
		fieldCode:     code,
		fieldMethod:   l.request.Method,
		fieldURL:      l.request.URL,
		fieldProtocol: l.request.Proto,
		fieldHeader:   l.request.Header,
		fieldPath:     logPath,
	}).Debug("Logging L7 flow record")

	if logBuf == nil {
		log.WithFields(log.Fields{
			fieldPath: logPath,
		}).Debug("Skipping writing to access log (write buffer nil)")
		return
	}

	b, err := json.Marshal(*l)
	if err != nil {
		logString(err.Error(), true)
	} else {
		logString(string(b), true)
	}

	if err := logBuf.Flush(); err != nil {
		log.WithFields(log.Fields{
			fieldPath: logPath,
		}).WithError(err).Warning("Error encountered while flushing to access log")
	}
}
