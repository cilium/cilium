package stacktrace

import (
	"strings"
	"testing"
)

func captureFunc() Stacktrace {
	return Capture(0)
}

func TestCaptureTestFunc(t *testing.T) {
	stack := captureFunc()

	if len(stack.Frames) == 0 {
		t.Fatal("expected stack frames to be returned")
	}

	// the first frame is the caller
	frame := stack.Frames[0]
	if expected := "captureFunc"; frame.Function != expected {
		t.Fatalf("expected function %q but recevied %q", expected, frame.Function)
	}
	expected := "/runc/libcontainer/stacktrace"
	if !strings.HasSuffix(frame.Package, expected) {
		t.Fatalf("expected package %q but received %q", expected, frame.Package)
	}
	if expected := "capture_test.go"; frame.File != expected {
		t.Fatalf("expected file %q but received %q", expected, frame.File)
	}
}
