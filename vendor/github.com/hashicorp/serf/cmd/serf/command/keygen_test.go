package command

import (
	"encoding/base64"
	"github.com/mitchellh/cli"
	"testing"
)

func TestKeygenCommand_implements(t *testing.T) {
	var _ cli.Command = &KeygenCommand{}
}

func TestKeygenCommand(t *testing.T) {
	ui := new(cli.MockUi)
	c := &KeygenCommand{Ui: ui}
	code := c.Run(nil)
	if code != 0 {
		t.Fatalf("bad: %d", code)
	}

	output := ui.OutputWriter.String()
	result, err := base64.StdEncoding.DecodeString(output)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if len(result) != 16 {
		t.Fatalf("bad: %#v", result)
	}
}
