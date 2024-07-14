// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/cilium/cilium/pkg/time"
)

//go:embed eventSummary.html
var eventSummaryHTML string

func writeBytes(p string, b []byte) error {
	return os.WriteFile(p, b, fileMode)
}

func writeString(p, v string) error {
	return writeBytes(p, []byte(v))
}

func writeTable(p string, o *metav1.Table) error {
	var b bytes.Buffer
	if err := printers.NewTablePrinter(printers.PrintOptions{
		Wide:          true,
		WithNamespace: true,
	}).PrintObj(o, &b); err != nil {
		return err
	}
	return writeString(p, b.String())
}

func writeYaml(p string, o runtime.Object) error {
	var j printers.YAMLPrinter
	w, err := printers.NewTypeSetter(scheme.Scheme).WrapToPrinter(&j, nil)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	if err := w.PrintObj(o, &b); err != nil {
		return err
	}
	return writeString(p, b.String())
}

// writeEventTable writes a html summary of cluster events.
func makeEventTable(events []corev1.Event) []byte {
	// sort events by time
	sort.Slice(events, func(i, j int) bool {
		return events[i].LastTimestamp.Time.Before(events[j].LastTimestamp.Time)
	})

	t := template.Must(template.New("events").Funcs(template.FuncMap{
		"formatTime": func(created, firstSeen, lastSeen metav1.Time, count int32) template.HTML {
			countMsg := ""
			if count > 1 {
				countMsg = fmt.Sprintf(" <small>(x%d)</small>", count)
			}
			if lastSeen.IsZero() {
				lastSeen = created
			}
			firstSeenUTC := firstSeen.In(time.UTC)
			lastSeenUTC := lastSeen.In(time.UTC)
			//nolint:gosec
			return template.HTML(fmt.Sprintf(`<time datetime="%s" title="First Seen: %s">%s</time>%s`, lastSeenUTC.String(), firstSeenUTC.Format("15:04:05Z"), lastSeenUTC.Format("15:04:05Z"), countMsg))
		},
		"reasonClass": func(r string) template.HTMLAttr {
			cssClass := "text-muted"
			switch {
			case strings.Contains(strings.ToLower(r), "fail"),
				strings.Contains(strings.ToLower(r), "error"),
				strings.Contains(strings.ToLower(r), "kill"),
				strings.Contains(strings.ToLower(r), "backoff"):
				cssClass = "text-danger"
			case strings.Contains(strings.ToLower(r), "notready"),
				strings.Contains(strings.ToLower(r), "unhealthy"),
				strings.Contains(strings.ToLower(r), "missing"):
				cssClass = "text-warning"
			}
			//nolint:gosec
			return template.HTMLAttr(fmt.Sprintf(`class="%s"`, cssClass))
		},
	}).Parse(eventSummaryHTML))

	out := bytes.NewBuffer([]byte{})
	if err := t.Execute(out, events); err != nil {
		panic(err) // unreachable
	}
	return out.Bytes()
}
