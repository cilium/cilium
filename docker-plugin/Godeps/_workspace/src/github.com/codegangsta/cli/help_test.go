package cli

import (
	"bytes"
	"testing"
)

func Test_ShowAppHelp_NoAuthor(t *testing.T) {
	output := new(bytes.Buffer)
	app := NewApp()
	app.Writer = output

	c := NewContext(app, nil, nil)

	ShowAppHelp(c)

	if bytes.Index(output.Bytes(), []byte("AUTHOR(S):")) != -1 {
		t.Errorf("expected\n%snot to include %s", output.String(), "AUTHOR(S):")
	}
}

func Test_ShowAppHelp_NoVersion(t *testing.T) {
	output := new(bytes.Buffer)
	app := NewApp()
	app.Writer = output

	app.Version = ""

	c := NewContext(app, nil, nil)

	ShowAppHelp(c)

	if bytes.Index(output.Bytes(), []byte("VERSION:")) != -1 {
		t.Errorf("expected\n%snot to include %s", output.String(), "VERSION:")
	}
}

func Test_Help_Custom_Flags(t *testing.T) {
	oldFlag := HelpFlag
	defer func() {
		HelpFlag = oldFlag
	}()

	HelpFlag = BoolFlag{
		Name:  "help, x",
		Usage: "show help",
	}

	app := App{
		Flags: []Flag{
			BoolFlag{Name: "foo, h"},
		},
		Action: func(ctx *Context) {
			if ctx.Bool("h") != true {
				t.Errorf("custom help flag not set")
			}
		},
	}
	output := new(bytes.Buffer)
	app.Writer = output
	app.Run([]string{"test", "-h"})
	if output.Len() > 0 {
		t.Errorf("unexpected output: %s", output.String())
	}
}

func Test_Version_Custom_Flags(t *testing.T) {
	oldFlag := VersionFlag
	defer func() {
		VersionFlag = oldFlag
	}()

	VersionFlag = BoolFlag{
		Name:  "version, V",
		Usage: "show version",
	}

	app := App{
		Flags: []Flag{
			BoolFlag{Name: "foo, v"},
		},
		Action: func(ctx *Context) {
			if ctx.Bool("v") != true {
				t.Errorf("custom version flag not set")
			}
		},
	}
	output := new(bytes.Buffer)
	app.Writer = output
	app.Run([]string{"test", "-v"})
	if output.Len() > 0 {
		t.Errorf("unexpected output: %s", output.String())
	}
}
