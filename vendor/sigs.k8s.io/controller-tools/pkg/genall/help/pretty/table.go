/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pretty

// TableCalculator calculates column widths (with optional padding)
// for a table based on the maximum required column width.
type TableCalculator struct {
	cellSizesByCol [][]int

	Padding  int
	MaxWidth int
}

// AddRowSizes registers a new row with cells of the given sizes.
func (c *TableCalculator) AddRowSizes(cellSizes ...int) {
	if len(cellSizes) > len(c.cellSizesByCol) {
		for range cellSizes[len(c.cellSizesByCol):] {
			c.cellSizesByCol = append(c.cellSizesByCol, []int(nil))
		}
	}
	for i, size := range cellSizes {
		c.cellSizesByCol[i] = append(c.cellSizesByCol[i], size)
	}
}

// ColumnWidths calculates the appropriate column sizes given the
// previously registered rows.
func (c *TableCalculator) ColumnWidths() []int {
	maxColWidths := make([]int, len(c.cellSizesByCol))

	for colInd, cellSizes := range c.cellSizesByCol {
		maxValue := 0
		for _, cellSize := range cellSizes {
			if maxValue < cellSize {
				maxValue = cellSize
			}
		}
		maxColWidths[colInd] = maxValue
	}

	actualMaxWidth := c.MaxWidth - c.Padding
	for i, width := range maxColWidths {
		if actualMaxWidth > 0 && width > actualMaxWidth {
			maxColWidths[i] = actualMaxWidth
		}
		maxColWidths[i] += c.Padding
	}

	return maxColWidths
}
