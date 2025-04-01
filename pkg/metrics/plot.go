// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"slices"
	"strings"

	"github.com/mitchellh/go-wordwrap"

	"github.com/cilium/cilium/pkg/time"
)

// PlotSamples plots the given samples as a line graph using the unicode braille characters.
func PlotSamples(w io.Writer, rate bool, name, labels string, timeSpan, samplingInterval time.Duration, samples []float32, sb SampleBitmap) {
	// Do not let panics propagate from here. Log the sample input that caused the panic.
	defer func() {
		if err := recover(); err != nil {
			_, file, line, _ := runtime.Caller(2)
			fmt.Fprintf(w, "panic: samples=%v, err=%s, source=%s:%d\n", samples, err, file, line)
		}
	}()

	title := name

	// Reverse the samples (samples is a fixed size array, thus was passed by value).
	// We want them ordered from oldest to newest the same as our X-axis.
	slices.Reverse(samples[:])
	if rate {
		// Compute the rate per second by iterating from oldest to newest and
		// subtracting the previous sample and dividing by our sampling
		// interval.
		prev := samples[0]
		for i := 1; i < len(samples); i++ {
			s := samples[i]
			samples[i] = (s - prev) / float32(samplingInterval.Seconds())
			prev = s
		}
		samples[0] = 0
		title += " (rate per second)"
	}
	sampleExists := func(index int) bool {
		if index < 0 || index >= len(samples) {
			return false
		}
		return sb.exists(len(samples) - 1 - int(index))
	}

	// Set up coordinates. We have two systems here, one for character
	// coordinates (width, height, originX, originY, plotHeight, plotWidth)
	// and one for the "dot" coordinates (plotHeightDots, plotWidthDots) using
	// the braille symbols and thus 4x the height and 2x the width.
	const width, height = 80, 10
	originX, originY := 11, 7
	plotHeight := height - 3
	plotHeightDots := plotHeight * 4
	plotWidth := width - originX - 1
	plotWidthDots := plotWidth * 2
	indentPlotOriginX := strings.Repeat(" ", originX)

	// Write the name of the metric at the center.
	fmt.Fprintf(w, "%s%s%s\n",
		indentPlotOriginX,
		strings.Repeat(" ", plotWidth/2-len(title)/2),
		title)

	// Write out the labels, also centered, but leave some margins.
	if labels != "" {
		for line := range strings.SplitSeq(wordwrap.WrapString(labels, uint(plotWidth-4)), "\n") {
			fmt.Fprintf(w, "%s%s[ %s ]\n",
				indentPlotOriginX,
				strings.Repeat(" ", plotWidth/2-(len(line)+4)/2),
				line)
		}
	}

	// Set up a canvas into which to draw in.
	canvas := make([]rune, width*height)
	for x := range width {
		for y := range height {
			if x >= originX && y <= originY {
				// initialize the plot area to the braille base. this way we can
				// just OR in the dots we want to show.
				canvas[y*width+x] = '\u2800'
			} else {
				canvas[y*width+x] = ' '
			}
		}
	}
	// setDot sets a braille dot within the dot coordinate system
	// (0,0)...(plotWidthDots,plotHeightDots).
	setDot := func(x, y int) {
		var braillePixels = [][]rune{
			{0x1, 0x2, 0x4, 0x40},    // left dots (even 'x')
			{0x08, 0x10, 0x20, 0x80}, // right
		}
		pos := rune((plotHeightDots - y - 1) % 4)
		canvas[(originY-y/4)*width+originX+x/2] |= braillePixels[x%2][pos]
	}
	writeText := func(y, x int, format string, args ...any) {
		copy(canvas[y*width+x:], []rune(fmt.Sprintf(format, args...)))
	}

	// Calculate the graph minimum and maximum values
	minY, maxY := float32(math.Inf(+1)), float32(math.Inf(-1))
	for _, y := range samples {
		minY = min(minY, y)
		maxY = max(maxY, y)
	}
	midY := (maxY + minY) / 2

	// Figure out how to show the Y units
	suffix := ""
	if strings.Contains(name, "seconds") {
		suffix = "s"
	}
	unit, multp := chooseUnit(float64(maxY))
	fmtY := func(v float32) string {
		return fmt.Sprintf("%.1f%s%s", v*float32(multp), unit, suffix)
	}

	// Render the labels and the box.
	writeText(0, originX-1, "╭"+strings.Repeat("─", width-originX-1)+"╮")
	writeText(1, 1, "%8s ┤", fmtY(maxY))
	writeText(1, width-1, "│")
	writeText(2, originX-1, "│")
	writeText(2, width-1, "│")
	writeText(3, originX-1, "│")
	writeText(3, width-1, "│")
	writeText(4, 1, "%8s ┤", fmtY(midY))
	writeText(4, width-1, "│")
	writeText(5, originX-1, "│")
	writeText(5, width-1, "│")
	writeText(6, originX-1, "│")
	writeText(6, width-1, "│")
	writeText(7, 1, "%8s ┤", fmtY(minY))
	writeText(7, width-1, "│")
	writeText(8, originX-1, "╰"+strings.Repeat("─", width-originX-1)+"╯")
	writeText(8, originX+3, "┬")
	writeText(9, originX, "-%.0fmin", timeSpan.Minutes())
	writeText(8, originX+3, "┬")
	writeText(8, originX+3+((width-10)/2)-3, "┬")
	writeText(9, originX+((width-10)/2)-3, "-%.0fmin", timeSpan.Minutes()/2)
	writeText(8, width-3, "┬")
	writeText(9, width-4, "now")

	// Normalize negative values for plotting
	if minY < 0.0 {
		for i := range samples {
			samples[i] += -minY
		}
		maxY += -minY
		minY = 0.0
	}
	if maxY == 0.0 {
		maxY = 0.000001
	}

	// getSample returns the interpolated sample for the given x position
	// in the dot coordinates.
	getSample := func(x int) (float32, bool) {
		// find which sample is closest to x (rounding down)
		pos := float64(x) / float64(plotWidthDots)
		index := int(float64(len(samples)-1) * pos)

		if !sampleExists(int(index)) {
			return 0.0, false
		} else if !sampleExists(index + 1) {
			// the next sample is either out of range or not present,
			// just return this sample without any interpolation.
			return samples[index], true
		}

		// interpolate between two samples for estimate value of 'x'
		prevPos := float64(index) / float64(len(samples)-1)
		nextPos := float64(index+1) / float64(len(samples)-1)
		rel := float32((pos - prevPos) / (nextPos - prevPos))

		return samples[index] + (samples[index+1]-samples[index])*rel, true
	}

	// mapToY maps the value to the Y position
	mapToY := func(v float32) int {
		return int(((v - minY) / maxY) * (float32(plotHeightDots) - 0.001))
	}

	// Plot the samples (up to second to last column)
	for x := range plotWidthDots - 1 {
		if v, exists := getSample(x); exists {
			setDot(x, mapToY(v))
		}
	}
	// Plot the last sample without interpolation so that we always show
	// the latest sample even if it's the only one.
	if sampleExists(len(samples) - 1) {
		setDot(
			plotWidthDots-1,
			mapToY(samples[len(samples)-1]),
		)
	}

	// Finally write out our canvas.
	for i := range height {
		fmt.Fprintln(w, string(canvas[i*width:i*width+width]))
	}
}
