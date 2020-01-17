package table_test

import (
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/extensions/table"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Math", func() {
	expectedResult := map[string]map[string]struct {
		description string
		expected    string
	}{
		"0": {
			"0": {
				description: "0 > 0",
				expected:    "false",
			},
			"1": {
				description: "0 > 1",
				expected:    "false",
			},
		},
		"1": {
			"0": {
				description: "1 > 0",
				expected:    "true",
			},
			"1": {
				description: "1 > 1",
				expected:    "false",
			},
		},
	}

	var entries []TableEntry
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			entries = append(entries, Entry(expectedResult[i][j].string, i, j, expectedResult[i][j].bool))
		}
	}
	DescribeTable("the > inequality",
		func(x int, y int, expected bool) {
			Expect(x > y).To(Equal(expected))
		},
		entries...,
	)
})

var _ = Describe("Substring matching", func() {
	type SubstringCase struct {
		String    string
		Substring string
		Count     int
	}

	DescribeTable("counting substring matches",
		func(c SubstringCase) {
			Ω(strings.Count(c.String, c.Substring)).Should(BeNumerically("==", c.Count))
		},
		Entry("with no matching substring", SubstringCase{
			String:    "the sixth sheikh's sixth sheep's sick",
			Substring: "emir",
			Count:     0,
		}),
		Entry("with one matching substring", SubstringCase{
			String:    "the sixth sheikh's sixth sheep's sick",
			Substring: "sheep",
			Count:     1,
		}),
		Entry("with many matching substring", SubstringCase{
			String:    "the sixth sheikh's sixth sheep's sick",
			Substring: "si",
			Count:     3,
		}),
	)
})

func TestBooks(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Books Suite")
}
