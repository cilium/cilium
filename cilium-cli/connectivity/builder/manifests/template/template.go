// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package template

import (
	"bytes"
	"html/template"
	"math/rand/v2"
	"net/netip"
	"strings"
	"time"
)

var (
	randGen = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0))
)

// Render executes temp template with data and returns the result
func Render(temp string, data any) (string, error) {
	fns := template.FuncMap{
		"trimSuffix": func(in, suffix string) string { return strings.TrimSuffix(in, suffix) },
		"ipToCIDR": func(ipString string) string {
			if ip, err := netip.ParseAddr(ipString); err == nil && ip.Is6() {
				return ipString + "/128" // IPv6 address
			} else {
				return ipString + "/32" // otherwise assume IPv4
			}
		},
		"generateDNSMatchPatternWithWildcard": GenerateDNSMatchPatternWithWildcard,
	}

	tm, err := template.New("template").Funcs(fns).Parse(temp)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	if err := tm.Execute(buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

type wildcardSpecifierType string

const (
	wildcardSpecifierTypeAnyPrefix       wildcardSpecifierType = "any-prefix"
	wildcardSpecifierTypeRandomAnyPrefix wildcardSpecifierType = "random-any-prefix"
	wildcardSpecifierTypeSubdomainPrefix wildcardSpecifierType = "subdomain-prefix"
	wildcardSpecifierTypeRandom          wildcardSpecifierType = "random"
)

func GenerateDNSMatchPatternWithWildcard(in, inExclusive string, typ wildcardSpecifierType) string {
	opLabels, commonLabels := SplitCommonSuffix(in, inExclusive, ".")
	// Labels to operate wildcard on must be greater than 1.
	if len(opLabels) <= 1 {
		return in
	}

	// Label indicating the first diff.
	diffLabel := opLabels[len(opLabels)-1]
	opLabels = opLabels[:len(opLabels)-1]

	switch typ {
	case wildcardSpecifierTypeAnyPrefix:
		opLabels = []string{"**"}

	case wildcardSpecifierTypeRandomAnyPrefix:
		replaceIdx := randGen.IntN(len(opLabels))
		opLabels = append([]string{"**"}, opLabels[replaceIdx+1:]...)

	case wildcardSpecifierTypeSubdomainPrefix:
		opLabels[0] = "*"

	case wildcardSpecifierTypeRandom:
		labelIdx := randGen.IntN(len(opLabels))
		label := opLabels[labelIdx]

		replaceStart := randGen.IntN(len(label))
		replaceEnd := replaceStart + randGen.IntN(len(label)-replaceStart) + 1
		opLabels[labelIdx] = label[:replaceStart] + "*" + label[replaceEnd:]

	default:
		return in
	}

	transformedLabels := append(opLabels, diffLabel)
	return strings.Join(append(transformedLabels, commonLabels...), ".") + "."
}

func SplitCommonSuffix(first string, second string, delimiter string) ([]string, []string) {
	first = strings.TrimSuffix(first, delimiter)
	second = strings.TrimSuffix(second, delimiter)

	if len(first) == 0 {
		return []string{}, []string{}
	}

	labelsFirst := strings.Split(first, delimiter)
	labelsSecond := strings.Split(second, delimiter)

	i := len(labelsFirst) - 1
	j := len(labelsSecond) - 1
	for i >= 0 && j >= 0 && labelsFirst[i] == labelsSecond[j] {
		i--
		j--
	}
	return labelsFirst[:i+1], labelsFirst[i+1:]
}
