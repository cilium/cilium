package logcmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/sirupsen/logrus"
)

type Logf = func(format string, args ...interface{})

func getLogfForLevel(log logrus.FieldLogger, lvl logrus.Level) Logf {
	switch lvl {
	case logrus.PanicLevel:
		return log.Panicf
	case logrus.FatalLevel:
		return log.Fatalf
	case logrus.ErrorLevel:
		return log.Errorf
	case logrus.WarnLevel:
		return log.Warnf
	case logrus.InfoLevel:
		return log.Infof
	case logrus.DebugLevel:
		return log.Debugf
	case logrus.TraceLevel:
		return log.Debugf
	default:
		// should not happen, but just return something anyway
		return log.Warnf
	}
}

func logReader(ctx context.Context, logF Logf, file *os.File, prefix string) error {

	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if err := file.SetDeadline(deadline); err != nil {
				logF("ctx deadline (%v) will not be respected", deadline)
			}
		}
	}

	rd := bufio.NewReader(file)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if os.IsTimeout(err) {
				return fmt.Errorf("read timeout due to context: %w", ctx.Err())
			}
			return err
		}

		logF("%s%s", prefix, line)
	}
}

func runAndLogCommand(
	ctx context.Context,
	cmd *exec.Cmd,
	logStdout, logStderr Logf,
) error {

	// prepare pipes
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("StdErrPipe() failed: %w", err)
	}
	defer stderr.Close()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("StdOutPipe() failed: %w", err)
	}
	defer stdout.Close()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	// cmd.StderrPipe() and cmd.StdoutPipe() docs say that we need to wait for the pipe reads to
	// finish, before waiting for the command using cmd.Wait(). However, if the command was
	// created with a timeout ctx, then the process will be killed only in cmd.Wait().
	//
	// to solve this problem, rsc suggests to use os.Pipe() and SetReadDeadline:
	// https://github.com/golang/go/issues/21922#issuecomment-338792340
	//
	// I was not sure how the pipes would be closed on the child end, but it seems that's taken
	// care by go itself:
	//  - https://github.com/golang/go/blob/bf2ef26be3593d24487311576d85ec601185fbf4/src/os/pipe_unix.go#L13-L28
	//  - https://github.com/golang/go/blob/bf2ef26be3593d24487311576d85ec601185fbf4/src/syscall/exec_unix.go#L19-L65
	//
	// Because I'm lazy, howerver, I'll just reuse the file descriptors from
	// cmd.Std{err,out}Pipe, since they are also calling os.Pipe():
	// - https://github.com/golang/go/blob/bf2ef26be3593d24487311576d85ec601185fbf4/src/os/exec/exec.go#L786
	// - https://github.com/golang/go/blob/bf2ef26be3593d24487311576d85ec601185fbf4/src/os/exec/exec.go#L761
	stderrFile := stderr.(*os.File)
	stdoutFile := stdout.(*os.File)

	// start logging
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err = logReader(ctx, logStdout, stdoutFile, "stdout> ")
		if err != nil {
			logStderr("failed to read from stdout: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		err = logReader(ctx, logStderr, stderrFile, "stderr> ")
		if err != nil {
			logStderr("failed to read from stdout: %v", err)
		}
	}()

	// we need to wait for the pipes before waiting for the command
	// see: https://pkg.go.dev/os/exec#Cmd.StdoutPipe
	wg.Wait()

	ret := cmd.Wait()
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return ret
}

func RunAndLogCommand(
	cmd *exec.Cmd,
	log logrus.FieldLogger,
) error {
	return runAndLogCommand(nil, cmd, getLogfForLevel(log, logrus.InfoLevel), getLogfForLevel(log, logrus.WarnLevel))
}

func logStart(log logrus.FieldLogger, cmd *exec.Cmd) {
	// start command
	xlog := log.WithField("path", cmd.Path).WithField("args", cmd.Args)
	if cwd, err := os.Getwd(); err == nil {
		xlog = xlog.WithField("cwd", cwd)
	}
	xlog.Info("starting command")
}

func RunAndLogCommandContext(
	ctx context.Context,
	log logrus.FieldLogger,
	cmd0 string,
	cmdArgs ...string,
) error {
	cmd := exec.CommandContext(ctx, cmd0, cmdArgs...)
	logStart(log, cmd)
	return runAndLogCommand(ctx, cmd, getLogfForLevel(log, logrus.InfoLevel), getLogfForLevel(log, logrus.WarnLevel))
}

func RunAndLogCommandsContext(
	ctx context.Context,
	log logrus.FieldLogger, // we should have something more flexible/generic here
	commands ...[]string,
) error {
	stdoutLog := getLogfForLevel(log, logrus.InfoLevel)
	stderrLog := getLogfForLevel(log, logrus.WarnLevel)
	for i := range commands {
		args := commands[i]
		if len(args) == 0 {
			return fmt.Errorf("command %d is empty", i)
		}
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		logStart(log, cmd)
		err := runAndLogCommand(ctx, cmd, stdoutLog, stderrLog)
		if err != nil {
			return fmt.Errorf("command %d failed: %w", i, err)
		}
	}

	return nil
}
