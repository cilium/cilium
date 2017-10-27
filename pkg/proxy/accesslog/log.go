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
	"github.com/cilium/cilium/pkg/logfields"

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
	FieldFilePath = logfields.Path
)

const (
	FieldKafkaApiKey        = "kafkaApiKey"
	FieldKafkaApiVersion    = "kafkaApiVersion"
	FieldKafkaCorrelationID = "kafkaCorrelationID"
)

// APIKeyMap is the map of all allowed kafka API keys
// with the key values.
// Reference: https://kafka.apache.org/protocol#protocol_api_keys
var APIKeyMap = map[int16]string{
	0:  "produce",              /* Produce */
	1:  "fetch",                /* Fetch */
	2:  "offsets",              /* Offsets */
	3:  "metadata",             /* Metadata */
	4:  "leaderandisr",         /* LeaderAndIsr */
	5:  "stopreplica",          /* StopReplica */
	6:  "updatemetadata",       /* UpdateMetadata */
	7:  "controlledshutdown",   /* ControlledShutdown */
	8:  "offsetcommit",         /* OffsetCommit */
	9:  "offsetfetch",          /* OffsetFetch */
	10: "findcoordinator",      /* FindCoordinator */
	11: "joingroup",            /* JoinGroup */
	12: "heartbeat",            /* Heartbeat */
	13: "leavegroup",           /* LeaveGroup */
	14: "syncgroup",            /* SyncGroup */
	15: "describegroups",       /* DescribeGroups */
	16: "listgroups",           /* ListGroups */
	17: "saslhandshake",        /* SaslHandshake */
	18: "apiversions",          /* ApiVersions */
	19: "createtopics",         /* CreateTopics */
	20: "deletetopics",         /* DeleteTopics */
	21: "deleterecords",        /* DeleteRecords */
	22: "initproducerid",       /* InitProducerId */
	23: "offsetforleaderepoch", /* OffsetForLeaderEpoch */
	24: "addpartitionstotxn",   /* AddPartitionsToTxn */
	25: "addoffsetstotxn",      /* AddOffsetsToTxn */
	26: "endtxn",               /* EndTxn */
	27: "writetxnmarkers",      /* WriteTxnMarkers */
	28: "txnoffsetcommit",      /* TxnOffsetCommit */
	29: "describeacls",         /* DescribeAcls */
	30: "createacls",           /* CreateAcls */
	31: "deleteacls",           /* DeleteAcls */
	32: "describeconfigs",      /* DescribeConfigs */
	33: "alterconfigs",         /* AlterConfigs */
}

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
		{
			l.HTTP = &LogRecordHTTP{
				Code:     code,
				Method:   l.HttpRequest.Method,
				URL:      l.HttpRequest.URL,
				Protocol: l.HttpRequest.Proto,
				Headers:  l.HttpRequest.Header,
			}
			log.WithFields(log.Fields{
				FieldType:     typ,
				FieldVerdict:  verdict,
				FieldCode:     code,
				FieldMethod:   l.HttpRequest.Method,
				FieldURL:      l.HttpRequest.URL,
				FieldProtocol: l.HttpRequest.Proto,
				FieldHeader:   l.HttpRequest.Header,
				FieldFilePath: logPath,
			}).Debug("Logging HTTP L7 flow record")

			if logBuf == nil {
				log.WithFields(log.Fields{
					FieldFilePath: logPath,
				}).Debug("Skipping writing to access log (write buffer nil)")
				return
			}

			b, err := json.Marshal(*l)
			if err != nil {
				logString(err.Error(), true)
			} else {
				logString(string(b), true)
			}
		}
	case L7TypeKafka:
		{
			l.Kafka = &LogRecordKafka{
				Code:          code,
				APIVersion:    l.KafkaRequest.GetVersion(),
				APIKey:        APIKeyMap[l.KafkaRequest.GetAPIKey()],
				CorrelationID: l.KafkaRequest.GetCorrelationID(),
			}

			log.WithFields(log.Fields{
				FieldType:               typ,
				FieldVerdict:            verdict,
				FieldCode:               code,
				FieldKafkaApiKey:        APIKeyMap[l.KafkaRequest.GetAPIKey()],
				FieldKafkaApiVersion:    l.KafkaRequest.GetVersion(),
				FieldKafkaCorrelationID: l.KafkaRequest.GetCorrelationID(),
				FieldFilePath:           logPath,
			}).Debug("Logging Kafka L7 flow record")

			if logBuf == nil {
				log.WithFields(log.Fields{
					FieldFilePath: logPath,
				}).Debug("Skipping writing to access log (write buffer nil)")
				return
			}

			/*
			 *	Log multiple entries for multiple Kafka topics in a single
			 *  request.
			 *  GH #1815
			 */

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

	}
	if err := logBuf.Flush(); err != nil {
		log.WithFields(log.Fields{
			FieldFilePath: logPath,
		}).WithError(err).Warning("Error encountered while flushing to access log")
	}
}
