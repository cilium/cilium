// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"fmt"
	"sort"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
)

type StatusCode int

const (
	OK       StatusCode = 0
	Warning  StatusCode = -1
	Failure  StatusCode = -2
	Disabled StatusCode = -3
)

// StatusType represents the type for the given status, higher the value, higher
// the priority.
type StatusType int

const (
	BPF    StatusType = 200
	Policy StatusType = 100
	Other  StatusType = 0
)

type Status struct {
	Code  StatusCode `json:"code"`
	Msg   string     `json:"msg"`
	Type  StatusType `json:"status-type"`
	State string     `json:"state"`
}

func (sc StatusCode) String() string {
	switch sc {
	case OK:
		return "OK"
	case Warning:
		return "Warning"
	case Failure:
		return "Failure"
	case Disabled:
		return "Disabled"
	default:
		return "Unknown code"
	}
}

func (s Status) String() string {
	if s.Msg == "" {
		return fmt.Sprintf("%s", s.Code)
	}
	return fmt.Sprintf("%s - %s", s.Code, s.Msg)
}

type StatusResponse struct {
	KVStore    Status              `json:"kvstore"`
	Docker     Status              `json:"docker"`
	Kubernetes Status              `json:"kubernetes"`
	Cilium     Status              `json:"cilium"`
	IPAMStatus map[string][]string `json:",omitempty"`
}

// statusLogMsg represents a log message.
type statusLogMsg struct {
	Status    Status    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// statusLog represents a slice of statusLogMsg.
type statusLog []*statusLogMsg

// componentStatus represents a map of a single statusLogMsg by StatusType.
type componentStatus map[StatusType]*statusLogMsg

// contains checks if the given `s` statusLogMsg is present in the
// priorityStatus.
func (ps componentStatus) contains(s *statusLogMsg) bool {
	return ps[s.Status.Type] == s
}

// statusTypeSlice represents a slice of StatusType, is used for sorting
// purposes.
type statusTypeSlice []StatusType

// Len returns the length of the slice.
func (p statusTypeSlice) Len() int { return len(p) }

// Less returns true if the element `j` is less than element `i`.
// *It's reversed* so that we can sort the slice by high to lowest priority.
func (p statusTypeSlice) Less(i, j int) bool { return p[i] > p[j] }

// Swap swaps element in `i` with element in `j`.
func (p statusTypeSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// sortByPriority returns a statusLog ordered from highest priority to lowest.
func (ps componentStatus) sortByPriority() statusLog {
	prs := statusTypeSlice{}
	for k := range ps {
		prs = append(prs, k)
	}
	sort.Sort(prs)
	slogSorted := statusLog{}
	for _, pr := range prs {
		slogSorted = append(slogSorted, ps[pr])
	}
	return slogSorted
}

// EndpointStatus represents the endpoint status.
type EndpointStatus struct {
	// CurrentStatuses is the last status of a given priority.
	CurrentStatuses componentStatus `json:"current-status,omitempty"`
	// Contains the last maxLogs messages for this endpoint.
	Log statusLog `json:"log,omitempty"`
	// Index is the index in the statusLog, is used to keep track the next
	// available position to write a new log message.
	Index int `json:"index"`
	// indexMU is the Mutex for the CurrentStatus and Log RW operations.
	indexMU lock.RWMutex
}

func NewEndpointStatus() *EndpointStatus {
	return &EndpointStatus{
		CurrentStatuses: componentStatus{},
		Log:             statusLog{},
	}
}

func (e *EndpointStatus) lastIndex() int {
	lastIndex := e.Index - 1
	if lastIndex < 0 {
		return maxLogs - 1
	}
	return lastIndex
}

// getAndIncIdx returns current free slot index and increments the index to the
// next index that can be overwritten.
func (e *EndpointStatus) getAndIncIdx() int {
	idx := e.Index
	e.Index++
	if e.Index >= maxLogs {
		e.Index = 0
	}
	// Lets skip the CurrentStatus message from the log to prevent removing
	// non-OK status!
	if e.Index < len(e.Log) &&
		e.CurrentStatuses.contains(e.Log[e.Index]) &&
		e.Log[e.Index].Status.Code != OK {
		e.Index++
		if e.Index >= maxLogs {
			e.Index = 0
		}
	}
	return idx
}

// addStatusLog adds statusLogMsg to endpoint log.
// example of e.Log's contents where maxLogs = 3 and Index = 0
// [index] - Priority - Code
// [0] - BPF - OK
// [1] - Policy - Failure
// [2] - BPF - OK
// With this log, the CurrentStatus will keep [1] for Policy priority and [2]
// for BPF priority.
//
// Whenever a new statusLogMsg is received, that log will be kept in the
// CurrentStatus map for the statusLogMsg's priority.
// The CurrentStatus map, ensures non of the failure messages are deleted for
// higher priority messages and vice versa.
func (e *EndpointStatus) addStatusLog(s *statusLogMsg) {
	e.CurrentStatuses[s.Status.Type] = s
	idx := e.getAndIncIdx()
	if len(e.Log) < maxLogs {
		e.Log = append(e.Log, s)
	} else {
		e.Log[idx] = s
	}
}

func (e *EndpointStatus) GetModel() []*models.EndpointStatusChange {
	e.indexMU.RLock()
	defer e.indexMU.RUnlock()

	list := []*models.EndpointStatusChange{}
	for i := e.lastIndex(); ; i-- {
		if i < 0 {
			i = maxLogs - 1
		}
		if i < len(e.Log) && e.Log[i] != nil {
			list = append(list, &models.EndpointStatusChange{
				Timestamp: e.Log[i].Timestamp.Format(time.RFC3339),
				Code:      e.Log[i].Status.Code.String(),
				Message:   e.Log[i].Status.Msg,
				State:     models.EndpointState(e.Log[i].Status.State),
			})
		}
		if i == e.Index {
			break
		}
	}
	return list
}

func (e *EndpointStatus) CurrentStatus() StatusCode {
	e.indexMU.RLock()
	defer e.indexMU.RUnlock()
	sP := e.CurrentStatuses.sortByPriority()
	for _, v := range sP {
		if v.Status.Code != OK {
			return v.Status.Code
		}
	}
	return OK
}

func (e *EndpointStatus) String() string {
	return e.CurrentStatus().String()
}
