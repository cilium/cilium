package scoped

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type Labels map[string]string

// Returns deterministic string representation of labels.
func (l Labels) String() string {
	keys := maps.Keys(l)
	sort.Strings(keys)
	kvs := []string{}
	for _, key := range keys {
		kvs = append(kvs, key+"="+l[key])
	}
	return strings.Join(kvs, ",")
}

type status struct {
	cell.Level
	Message string
	Err     error
}

type scopedReporter struct {
	lock.Mutex
	labels   Labels
	status   map[string]status
	degraded func(message string, err error)
	ok       func(message string)
}

func (s *scopedReporter) OK(message string) { s.ok(message) }

func (s *scopedReporter) Degraded(message string, err error) { s.degraded(message, err) }
func (s *scopedReporter) Stopped(message string) {
	// noop?
	log.Warn("stopped called on scoped reporter")
}

func (s *scopedReporter) clear(id string) {
	s.Lock()
	defer s.Unlock()
	delete(s.status, id)
}

func WithLabels(ctx context.Context, hr cell.HealthReporter, labels Labels) *scopedReporter {
	sr := &scopedReporter{
		labels: labels,
		status: make(map[string]status),
	}
	id := labels.String()
	if parent, ok := hr.(*scopedReporter); ok {
		// If the parent is a scoped reporter, then we add updates to that
		// and emit a degraded update containing all degraded children.
		sr.degraded = func(message string, err error) {
			parent.Lock()
			defer parent.Unlock()
			// Add itself to the parent.
			parent.status[id] = status{
				Level:   cell.StatusDegraded,
				Message: message,
				Err:     err,
			}
			// Bubble up the latest set of errors!
			var errs error
			for _, child := range parent.status {
				switch child.Level {
				case cell.StatusDegraded:
					errs = errors.Join(errs, child.Err)
				default:
				}
			}
			// Say this is cc2
			// Then this is calling out to c2.hr which is the root.
			parent.degraded(message, err)
		}
		sr.ok = func(message string) {
			// Check if this reporter is all clear, if so remove itself from
			// the parent and call ok on the parent, which will attempt to do
			// the same if it is a scoped reporter.
			parent.Lock()
			defer parent.Unlock()
			delete(parent.status, id)
			allok := true
			var errs error
			messages := []string{}
			// Check if this reporter is all clear,
			for _, child := range parent.status {
				switch child.Level {
				case cell.StatusOK:
				case cell.StatusDegraded:
					allok = false
					messages = append(messages, child.Message)
					errs = errors.Join(errs, child.Err)
				case cell.StatusUnknown:
				case cell.StatusStopped:
				}
			}
			if allok {
				// Remove itself from the parent, all children are ok.
				parent.ok(message)
			} else {
				parent.degraded(strings.Join(messages, ",")+": "+labels.String(), errs)
			}
		}

		go func() {
			<-ctx.Done()
			fmt.Println("reporter closed!", sr.labels.String())
			sr.ok("subreporter completed")
		}()
	} else {
		// If this is a root scoped reporter, then we emit degraded updates
		// directly.
		sr.degraded = func(message string, err error) {
			fmt.Println("calling actual reporter-> Degrade")
			hr.Degraded(message, err)
		}
		sr.ok = func(message string) {
			fmt.Println("calling actual reporter-> OK")
			hr.OK(message)
		}
	}
	return sr
}

type rateLimitedReporter struct {
	lock.Mutex
	hr          cell.HealthReporter
	minDuration time.Duration
	lastEmit    time.Time
}

func WithRateLimit(hr cell.HealthReporter, d time.Duration) *rateLimitedReporter {
	return &rateLimitedReporter{
		hr:          hr,
		minDuration: d,
	}
}

func (r *rateLimitedReporter) OK(message string) {
	r.Lock()
	defer r.Unlock()
	if time.Since(r.lastEmit) < r.minDuration {
		return
	}
	r.hr.OK(message)
	r.lastEmit = time.Now()
}

func (r *rateLimitedReporter) Degraded(message string, err error) {
	if time.Since(r.lastEmit) < r.minDuration {
		return
	}
	r.hr.Degraded(message, err)
	r.lastEmit = time.Now()
}

func (r *rateLimitedReporter) Stopped(message string) {
	if time.Since(r.lastEmit) < r.minDuration {
		return
	}
	r.hr.Stopped(message)
	r.lastEmit = time.Now()
}
