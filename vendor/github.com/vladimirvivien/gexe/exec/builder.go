package exec

import (
	"sync"
)

type CommandPolicy byte

const (
	CmdOnErrContinue CommandPolicy = 1 << iota
	CmdOnErrExit
	CmdExecSerial
	CmdExecConcurrent
	CmdExecPipe
)

type CommandProcs struct {
	procs []*Proc
}
type CommandBuilder struct {
	cmdPolicy CommandPolicy
	procs     []*Proc
	procChan  chan *Proc
}

// Commands creates a *CommandBuilder used to collect
// command strings to be executed.
func Commands(cmds ...string) *CommandBuilder {
	cb := new(CommandBuilder)
	for _, cmd := range cmds {
		cb.procs = append(cb.procs, NewProc(cmd))
	}
	return cb
}

// WithPolicy sets one or more command policy mask values, i.e. (CmdOnErrContinue | CmdExecConcurrent)
func (cb *CommandBuilder) WithPolicy(policyMask CommandPolicy) *CommandBuilder {
	cb.cmdPolicy = policyMask
	return cb
}

// Add adds a new command string to the builder
func (cb *CommandBuilder) Add(cmds ...string) *CommandBuilder {
	for _, cmd := range cmds {
		cb.procs = append(cb.procs, NewProc(cmd))
	}
	return cb
}

// Run is a shortcut for executing the procs serially:
//
//   cb.WithPolicy(CmdOnErrContinue).Start().Wait()
//
func (cb *CommandBuilder) Run() CommandProcs {
	return cb.WithPolicy(CmdOnErrContinue).Start().Wait()
}

// ConcurRun is a shortcut for executing procs concurrently:
//
//   cb.WithPolicy(CmdExecConcurrent).Start().Wait()
//
func (cb *CommandBuilder) ConcurRun() CommandProcs {
	return cb.WithPolicy(CmdOnErrContinue | CmdExecConcurrent).Start().Wait()
}

// Start starts running the registered procs serially and returns immediately.
// This should be followed by a call to Wait to retrieve results.
func (cb *CommandBuilder) Start() *CommandBuilder {
	if len(cb.procs) == 0 {
		return cb
	}

	cb.procChan = make(chan *Proc, len(cb.procs))
	switch {
	case hasPolicy(cb.cmdPolicy, CmdExecConcurrent):
		// launch each command in its own goroutine
		go func() {
			defer close(cb.procChan)
			var gate sync.WaitGroup
			for _, proc := range cb.procs {
				gate.Add(1)
				go func(wg *sync.WaitGroup, ch chan<- *Proc, p *Proc) {
					defer wg.Done()
					ch <- p.Start()
				}(&gate, cb.procChan, proc)
			}
			// wait for procs to launch
			gate.Wait()
		}()

	case hasPolicy(cb.cmdPolicy, CmdExecPipe):
		// pipe successive commands serially
		go func(ch chan<- *Proc) {
			defer close(cb.procChan)
			if len(cb.procs) == 1 {
				ch <- cb.procs[0].Start()
				return
			}
		}(cb.procChan)
	default:
		// launch all procs (serially), return immediately
		go func(ch chan<- *Proc) {
			defer close(cb.procChan)
			for _, proc := range cb.procs {
				ch <- proc.Start()
			}
		}(cb.procChan)
	}
	return cb
}

func (cb *CommandBuilder) Wait() CommandProcs {
	if len(cb.procs) == 0 || cb.procChan == nil {
		return CommandProcs{procs: []*Proc{}}
	}

	var result CommandProcs
	for proc := range cb.procChan {
		result.procs = append(result.procs, proc)

		// check for start err
		if proc.Err() != nil {
			if hasPolicy(cb.cmdPolicy, CmdOnErrExit) {
				break
			}
		}

		// wait for command to complete
		if err := proc.Wait().Err(); err != nil {
			if hasPolicy(cb.cmdPolicy, CmdOnErrExit) {
				break
			}
		}
	}
	return result
}

func hasPolicy(mask, pol CommandPolicy) bool {
	return (mask & pol) != 0
}

// TODO - add termination methods
// - Pipe() - Runs each command, piping result of prev command into std input of next command
