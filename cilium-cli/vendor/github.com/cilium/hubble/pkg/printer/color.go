// Copyright 2021 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package printer

import (
	"strings"

	"github.com/fatih/color"
)

type sprinter interface {
	Sprint(a ...interface{}) string
}

type colorer struct {
	colors  []*color.Color
	red     sprinter
	green   sprinter
	blue    sprinter
	cyan    sprinter
	magenta sprinter
	yellow  sprinter
}

func newColorer(when string) *colorer {
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgCyan)
	magenta := color.New(color.FgMagenta)
	yellow := color.New(color.FgYellow)

	c := &colorer{
		red:     red,
		green:   green,
		blue:    blue,
		cyan:    cyan,
		magenta: magenta,
		yellow:  yellow,
	}

	c.colors = []*color.Color{
		red, green, blue,
		cyan, magenta, yellow,
	}
	switch strings.ToLower(when) {
	case "always":
		c.enable()
	case "never":
		c.disable()
	case "auto":
		c.auto()
	}
	return c
}

func (c *colorer) auto() {
	for _, v := range c.colors {
		if color.NoColor { // NoColor is global and set dynamically
			v.DisableColor()
		} else {
			v.EnableColor()
		}
	}
}

func (c *colorer) enable() {
	for _, v := range c.colors {
		v.EnableColor()
	}
}

func (c *colorer) disable() {
	for _, v := range c.colors {
		v.DisableColor()
	}
}

func (c colorer) port(a interface{}) string {
	return c.yellow.Sprint(a)
}

func (c colorer) host(a interface{}) string {
	return c.cyan.Sprint(a)
}

func (c colorer) verdictForwarded(a interface{}) string {
	return c.green.Sprint(a)
}

func (c colorer) verdictDropped(a interface{}) string {
	return c.red.Sprint(a)
}

func (c colorer) verdictAudit(a interface{}) string {
	return c.yellow.Sprint(a)
}
