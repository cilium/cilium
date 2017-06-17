package bpfloader

import (
	"fmt"
	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/util/exec"
	"runtime"
	"strings"
)

type loaderCommand struct {
	cmd                 string
	ignoreAllErr        bool
	ignoreErrIfContains string
}

func execute(cmd string, ignoreAnyErr bool, ignoreErrIfContains string) (string, error) {
	output, err := command(cmd)
	strout := string(output)
	strings.TrimSuffix(strout, "\n")
	if err == nil {
		return strout, nil
	}
	if ignoreAnyErr || (ignoreErrIfContains != "" && strings.Contains(err.Error(), ignoreErrIfContains)) {
		glog.Infof("%v ", err)
		glog.Infof("caller: %s ", getCaller())
		return strout, nil
	}
	return strout, err
}

func command(cmd string) ([]byte, error) {
	exec := exec.New()
	output, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s failed due to %v : %s", cmd, err, string(output))
	}
	return output, err
}

func getCaller() string {
	var pc [1]uintptr
	runtime.Callers(3, pc[:])
	f := runtime.FuncForPC(pc[0])
	if f == nil {
		return fmt.Sprintf("Unable to find caller")
	}
	return f.Name()
}
