// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/lock"
)

// Task represents any task that can be run to produce bugtool dump data.
type Task interface {
	// Run schedules a task run, with dir being the directory in which all final
	// dump output should be written.
	Run(context.Context, Context) error

	// Identifier returns an identifier string of the task, including
	// the type and name.
	//
	// By default this will be the same as the internal base identifier function,
	// however it may be overridden.
	Identifier() string

	// Validate recursively checks that the task configuration is valid.
	Validate(context.Context) error
}

var (
	_ Task = &Exec{}
	_ Task = &Dir{}
	_ Task = &Request{}
	_ Task = &File{}
)

// ScheduleFunc schedules another function for execution.
type ScheduleFunc func(string, func(context.Context) error) error

// Context is the runtime context of a task tree.
//
// This is used to share common Task scheduling and reporting functionality
// down the execution tree.
type Context struct {
	dir string

	SubmitFn ScheduleFunc

	// Note: Do not change pointer after init, will be accessed concurrently.
	collect *collector
}

func (c Context) Submit(ctx context.Context, identifier string, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("did not start task %q: %w", identifier, err)
	}
	return c.SubmitFn(identifier, fn)
}

// NewContext constructs a new contexts, where baseDir should be the root of the
// dump directory.
func NewContext(baseDir string, submit ScheduleFunc) Context {
	return Context{
		dir:      baseDir,
		SubmitFn: submit,
		collect:  &collector{results: make(map[string]*TopicResults)},
	}
}

// TaskResult contains result metadata about the outcome of a tasks execution.
type TaskResult struct {
	Name           string    `json:"name"`
	StartTime      time.Time `json:"start_time"`
	Duration       string    `json:"duration"`
	OutputFilePath string    `json:"output_file,omitempty"`

	Code  int   `json:"return_code"`
	Error error `json:"error,omitempty"`

	UserTime           int64 `json:"user_time"`
	KernelTime         int64 `json:"kernel_time"`
	MaxResidentSetSize int64 `json:"max_resident_set_size"`
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
	lock.RWMutex
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
