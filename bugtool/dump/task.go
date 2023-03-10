// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

var (
	_ Task = &Exec{}
	_ Task = &Dir{}
	_ Task = &Request{}
	_ Task = &File{}
	_ Task = &BPFMap[*bytes.Buffer, interface{}]{}
)

// ScheduleFunc schedules another function for execution.
type ScheduleFunc func(string, func(context.Context) error) error

// Context is the runtime context of a task tree. It is used to pass
// scheduling and reporting functionality down the execution tree.
type Context struct {
	dir     string
	timeout time.Duration

	Submit ScheduleFunc

	// Note: Do not change pointer after init, will be accessed concurrently.
	collect *collector
}

// NewContext constructs a new contexts, where baseDir should be the root of the
// dump directory.
func NewContext(baseDir string, submit ScheduleFunc, timeout time.Duration) Context {
	return Context{
		dir:     baseDir,
		Submit:  submit,
		timeout: timeout,
		collect: &collector{results: make(map[string]*TopicResults)},
	}
}

// TaskResult contains result metadata about the outcome of a tasks execution.
type TaskResult struct {
	Name           string    `json:"name"`
	StartTime      time.Time `json:"start_time"`
	Duration       string    `json:"duration"`
	OutputFilePath string    `json:"output_file,omitempty"`

	Code  int             `json:"return_code"`
	Error error           `json:"error,omitempty"`
	Usage *syscall.Rusage `json:"usage,omitempty"`
}

type TopicResults struct {
	Name    string       `json:"name"`
	Results []TaskResult `json:"results"`
}

func (c Context) GetResults() error {
	for p, v := range c.collect.results {
		file := path.Join(p, "results.yaml")
		fd, err := os.Create(file)
		if err != nil {
			return fmt.Errorf("failed to create results file: %w", err)
		}
		d, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}
		if _, err := fd.Write(d); err != nil {
			return fmt.Errorf("failed to write results %q: %w", file, err)
		}
		fd.Close()
	}
	return nil
}

// collector collects results from tasks.
type collector struct {
	sync.RWMutex
	results map[string]*TopicResults
}

func (c Context) AddResult(r TaskResult) {
	c.collect.addResult(c.dir, r)
}

func (c *collector) addResult(dir string, r TaskResult) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.results[dir]; !ok {
		c.results[dir] = &TopicResults{
			Name: dir,
		}
	}
	c.results[dir].Results = append(c.results[dir].Results, r)
}

// Dir is the current output directory where tasks running under this Context
// should write their output.
func (c Context) Dir() string {
	return c.dir
}

// WithSubdir creates a new runtime context, under a new subdirectory.
// This is useful for creating tasks in subdirectories.
func (c Context) WithSubdir(name string) Context {
	c.dir = path.Join(c.dir, name)
	return c
}

// CreateFile attempts to create a file in the current runtime contexts
// directory.
func (c Context) CreateFile(filename string) (*os.File, error) {
	filepath := path.Join(c.dir, filename)
	return os.Create(filepath)
}

// CreateFile attempts to create a file in the current runtime contexts
// directory.
func (c Context) CreateErrFile(filename string) (*ErrFile, error) {
	fd, err := c.CreateFile(filename)
	return createErrFile(path.Join(c.dir, filename), fd), err
}

// Initialize initializes a runtime context, ensuring that dump directory is in place.
func Initialize(c Context) error {
	if c.Dir() == "" {
		return nil
	}
	if err := os.MkdirAll(c.Dir(), dumpDirPerms); err != nil {
		logrus.Errorf("could not init dir %q: %s", c.Dir(), err.Error())
		return fmt.Errorf("could not init dump directory %q: %w", c.Dir(), err)
	}
	return nil
}

func (c Context) Logger() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		// todo
	})
}

// Task represents any task that can be run to produce bugtool dump data.
type Task interface {
	// Run schedules a task run, with dir being the directory in which all final
	// dump output should be written.
	Run(context.Context, Context) error

	// GetName returns the name of the task.
	GetName() string

	// Identifier returns an identifier string of the task, including
	// the type and name.
	Identifier() string

	// Validate recursively checks that the task configuration is valid.
	Validate(context.Context) error
}

// Tasks is a collection of Task structs.
type Tasks []Task

type Clause func(dir string, ctx context.Context) (bool, error)

func EvalClauses(dir string, ctx context.Context, cs []Clause) (bool, error) {
	for _, clause := range cs {
		if ok, err := clause(dir, ctx); !ok || err != nil {
			return ok, err
		}
	}
	return true, nil
}
