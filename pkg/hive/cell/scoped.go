package cell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
	"golang.org/x/exp/maps"
)

func Reporter[T any]() *scopedReporterCell[T] {
	var v T
	return &scopedReporterCell[T]{
		name: reflect.TypeOf(v).Name(),
	}
}

type scopedReporterCell[T any] struct {
	name string
}

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
	Level
	Message        string
	Err            error
	renderCallback func(int, io.Writer)
}

type structuredReporter struct {
	lock.Mutex
	labels   Labels
	status   map[string]status
	degraded func(message string, err error)
	ok       func(message string)
	renderer renderer
}

type renderer interface {
	render(node status, indent int, w io.Writer)
}

var defaultRenderer = &statusRenderer{}

type statusRenderer struct{}

func (r *statusRenderer) render(node status, indent int, w io.Writer) {
	is := strings.Repeat(" ", indent)
	fmt.Fprintf(w, "%s%s: %s\n", is+is, node.Level, node.Message)
	if node.Err != nil {
		fmt.Fprintf(w, "%s%s\n", is+is+is, node.Err.Error())
	}
}

func (s *structuredReporter) render(indent int, w io.Writer) {
	s.Lock()
	defer s.Unlock()
	is := strings.Repeat(" ", indent)
	fmt.Fprintf(w, "%s%s:\n", is, s.labels.String())
	for _, child := range s.status {
		if s.renderer != nil {
			s.renderer.render(child, indent+2, w)
		} else {
			defaultRenderer.render(child, indent+2, w)
		}

		child.renderCallback(indent+2+2, w)
	}
}

func (s *structuredReporter) OK(message string) { s.ok(message) }

func (s *structuredReporter) Degraded(message string, err error) { s.degraded(message, err) }
func (s *structuredReporter) Stopped(message string) {
	log.Warn("stopped called on scoped reporter")
}

func WithLabels(ctx context.Context, hr HealthReporter, labels Labels) HealthReporter {
	return withLabels(ctx, hr, labels)
}

// This is what the dynamic reporter will look like, the context is kinda key?
// Ok so this thing can create a reporter out of anything.
func withLabels(ctx context.Context, hr HealthReporter, labels Labels) *structuredReporter {
	sr := &structuredReporter{
		labels: labels,
		status: make(map[string]status),
	}
	id := labels.String()
	if parent, ok := hr.(*structuredReporter); ok {
		// If the parent is a scoped reporter, then we add updates to that
		// and emit a degraded update containing all degraded children.
		sr.degraded = func(message string, err error) {
			parent.Lock()
			// Add itself to the parent.
			parent.status[id] = status{
				Level:          StatusDegraded,
				Message:        message,
				Err:            err,
				renderCallback: sr.render,
			}
			// Bubble up the latest set of errors!
			var errs error
			messages := []string{}
			for _, child := range parent.status {
				switch child.Level {
				case StatusDegraded:
					messages = append(messages, child.Message)
					errs = errors.Join(errs, child.Err)
				default:
				}
			}
			// We must unlock the parent before using it's degraded callback, since that
			// may trigger a render which will lock this reporter and cause a deadlock.
			parent.Unlock()
			parent.degraded(strings.Join(messages, ","), err)
		}
		sr.ok = func(message string) {
			// Check if this reporter is all clear, if so remove itself from
			// the parent and call ok on the parent, which will attempt to do
			// the same if it is a scoped reporter.
			parent.Lock()
			parent.status[id] = status{
				Level:          StatusOK,
				Message:        message,
				renderCallback: sr.render,
			}
			allok := true
			var errs error
			messages := []string{}
			okMessages := []string{}
			// Check if this reporter is all clear,
			for _, child := range parent.status {
				switch child.Level {
				case StatusOK:
					okMessages = append(okMessages, child.Message)
				case StatusDegraded:
					allok = false
					messages = append(messages, child.Message)
					errs = errors.Join(errs, child.Err)
				case StatusUnknown:
				case StatusStopped:
				}
			}
			// We must unlock the parent before using it's "ok" callback, since that
			// may trigger a render which will lock this reporter and cause a deadlock.
			parent.Unlock()
			if allok {
				// Remove itself from the parent, all children are ok.
				// Whos to say we need to use this API?
				parent.ok(strings.Join(okMessages, ","))
			} else {
				parent.degraded(strings.Join(messages, ",")+": "+labels.String(), errs)
			}
		}

		if ctx != nil {
			go func() {
				<-ctx.Done()
				sr.ok("")
			}()
		}

	} else {
		sr.degraded = func(message string, err error) {
			w := &strings.Builder{}
			sr.render(0, w)
			hr.Degraded(w.String(), err)
		}
		sr.ok = func(message string) {
			w := &strings.Builder{}
			sr.render(0, w)
			hr.OK(w.String())
		}
	}
	return sr
}
