package command

import (
	"github.com/mitchellh/cli"
	"strings"
	"testing"
)

func TestEventCommand_implements(t *testing.T) {
	var _ cli.Command = &EventCommand{}
}

func TestEventCommandRun_noEvent(t *testing.T) {
	ui := new(cli.MockUi)
	c := &EventCommand{Ui: ui}
	args := []string{"-rpc-addr=foo"}

	code := c.Run(args)
	if code != 1 {
		t.Fatalf("bad: %d", code)
	}

	if !strings.Contains(ui.ErrorWriter.String(), "event name") {
		t.Fatalf("bad: %#v", ui.ErrorWriter.String())
	}
}

func TestEventCommandRun_tooMany(t *testing.T) {
	ui := new(cli.MockUi)
	c := &EventCommand{Ui: ui}
	args := []string{"-rpc-addr=foo", "foo", "bar", "baz"}

	code := c.Run(args)
	if code != 1 {
		t.Fatalf("bad: %d", code)
	}

	if !strings.Contains(ui.ErrorWriter.String(), "Too many") {
		t.Fatalf("bad: %#v", ui.ErrorWriter.String())
	}
}
