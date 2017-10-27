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
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"

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

// fields used for structured logging of Kafka messages
const (
	FieldKafkaAPIKey        = "kafkaApiKey"
	FieldKafkaAPIVersion    = "kafkaApiVersion"
	FieldKafkaCorrelationID = "kafkaCorrelationID"
)

// L7Type
const (
	L7TypeHTTP = iota
	L7TypeKafka
)

// OpenLogfile opens a file for logging
func OpenLogfile(lf string) error {
	var err error

	if logFile, err = os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
		return err
	}

	logPath = lf
	log.WithFields(log.Fields{
		FieldFilePath: logPath,
	}).Debug("Opened access log")

	logBuf = bufio.NewWriter(logFile)
	return nil
}

// CloseLogfile closes the logfile
func CloseLogfile() {
	log.WithFields(log.Fields{
		FieldFilePath: logPath,
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
				FieldFilePath: logPath,
			}).WithError(err).Warning("Error encountered while writing to access log, retrying once...")

			CloseLogfile()
			OpenLogfile(logPath)

			// retry once
			logString(outStr, false)
		}
	}
}

// LogHTTP logs a HTTP record to the logfile
func LogHTTP(l *LogRecord, typ FlowType, verdict FlowVerdict, code int) {
	l.HTTP = &LogRecordHTTP{
		Code:     code,
		Method:   l.HTTPRequest.Method,
		URL:      l.HTTPRequest.URL,
		Protocol: l.HTTPRequest.Proto,
		Headers:  l.HTTPRequest.Header,
	}
	log.WithFields(log.Fields{
		FieldType:     typ,
		FieldVerdict:  verdict,
		FieldCode:     code,
		FieldMethod:   l.HTTPRequest.Method,
		FieldURL:      l.HTTPRequest.URL,
		FieldProtocol: l.HTTPRequest.Proto,
		FieldHeader:   l.HTTPRequest.Header,
		FieldFilePath: logPath,
	}).Debug("Logging HTTP L7 flow record")

	if logBuf == nil {
		log.WithField(FieldFilePath, logPath).
			Debug("Skipping writing to access log (write buffer nil)")
		return
	}

	b, err := json.Marshal(*l)
	if err != nil {
		logString(err.Error(), true)
	} else {
		logString(string(b), true)
	}
}

func apiKeyToString(apiKey int16) string {
	if key, ok := api.KafkaReverseAPIKeyMap[apiKey]; ok {
		return key
	}
	return fmt.Sprintf("%d", apiKey)
}

// LogKafka logs a Kafka record to the logfile
func LogKafka(l *LogRecord, typ FlowType, verdict FlowVerdict, code int) {
	apiKey := l.KafkaRequest.GetAPIKey()

	l.Kafka = &LogRecordKafka{
		ErrorCode:     code,
		APIVersion:    l.KafkaRequest.GetVersion(),
		APIKey:        apiKeyToString(apiKey),
		CorrelationID: l.KafkaRequest.GetCorrelationID(),
	}

	log.WithFields(log.Fields{
		FieldType:               typ,
		FieldVerdict:            verdict,
		FieldCode:               code,
		FieldKafkaAPIKey:        apiKeyToString(apiKey),
		FieldKafkaAPIVersion:    l.KafkaRequest.GetVersion(),
		FieldKafkaCorrelationID: l.KafkaRequest.GetCorrelationID(),
		FieldFilePath:           logPath,
	}).Debug("Logging Kafka L7 flow record")

	if logBuf == nil {
		log.WithField(FieldFilePath,
			logPath).Debug("Skipping writing to access log (write buffer nil)")
		return
	}

	//
	// Log multiple entries for multiple Kafka topics in a single
	// request. GH #1815
	//

	topics := l.KafkaRequest.GetTopics()
	for i := 0; i < len(topics); i++ {
		l.Kafka.Topic.Topic = topics[i]
		b, err := json.Marshal(*l)
		if err != nil {
			logString(err.Error(), true)
		} else {
			logString(string(b), true)
		}
	}
}

// Log logs a record to the logfile and flushes the buffer
func Log(l *LogRecord, typ FlowType, verdict FlowVerdict, code int, L7type int) {
	// Lock while writing access log so we serialize writes as we may have
	// to reopen the logfile and parallel writes could fail because of that
	logMutex.Lock()
	defer logMutex.Unlock()

	l.Type = typ
	l.Verdict = verdict
	l.Metadata = metadata

	switch L7type {
	case L7TypeHTTP:
		LogHTTP(l, typ, verdict, code)
	case L7TypeKafka:
		LogKafka(l, typ, verdict, code)
	}

	if logBuf != nil {
		if err := logBuf.Flush(); err != nil {
			log.WithError(err).WithField(FieldFilePath,
				logPath).Warn("Error encountered while flushing to access log")
		}
	}
}
