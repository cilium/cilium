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
	"fmt"
	"os"
)

var (
	logFile  *os.File
	logBuf   *bufio.Writer
	metadata []string
)

// OpenLogfile opens a file for logging
func OpenLogfile(lf string) error {
	var err error

	if logFile, err = os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
		return err
	}

	logBuf = bufio.NewWriter(logFile)
	return nil
}

// CloseLogfile closes the logfile
func CloseLogfile() {
	logBuf.Flush()
	logFile.Close()
}

// SetMetadata sets the metadata to include in each record
func SetMetadata(md []string) {
	metadata = md
}

// Log logs a record to the logfile and flushes the buffer
func Log(l *LogRecord, typ FlowType, verdict FlowVerdict, code int) {
	if logBuf == nil {
		return
	}

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

	b, err := json.Marshal(*l)
	if err != nil {
		fmt.Fprintln(logBuf, err.Error())
	} else {
		fmt.Fprintln(logBuf, string(b))
	}

	logBuf.Flush()
}
