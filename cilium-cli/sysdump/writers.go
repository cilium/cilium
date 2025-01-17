// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

//go:embed eventSummary.html
var eventSummaryHTML string

func writeTable(obj *metav1.Table, out io.Writer) error {
	return printers.NewTablePrinter(printers.PrintOptions{
		Wide:          true,
		WithNamespace: true,
	}).PrintObj(obj, out)
}

func writeYAML(obj runtime.Object, out io.Writer) error {
	delegate := printers.ResourcePrinter(&printers.YAMLPrinter{})
	if meta.IsListType(obj) && meta.LenList(obj) > 0 {
		// Print lists one item at a time, to reduce the amount of memory used by the printer.
		delegate = printers.ResourcePrinterFunc(func(obj runtime.Object, out io.Writer) error {
			_, err := fmt.Fprintf(out, "apiVersion: %s\nitems:\n", obj.GetObjectKind().GroupVersionKind().GroupVersion())
			if err != nil {
				return err
			}

			if err := meta.EachListItem(obj, func(item runtime.Object) error {
				data, err := yaml.Marshal(item)
				if err != nil {
					return err
				}

				_, err = indentAsListItem(data, out)
				return err
			}); err != nil {
				return err
			}

			_, err = fmt.Fprintf(out, "kind: %s\n", obj.GetObjectKind().GroupVersionKind().Kind)
			if err != nil {
				return err
			}

			if listMeta, err := meta.ListAccessor(obj); err == nil {
				if rv := listMeta.GetResourceVersion(); rv != "" {
					_, err = fmt.Fprintf(out, "metadata:\n  resourceVersion: %q\n", rv)
				} else {
					_, err = fmt.Fprint(out, "metadata: {}\n", rv)
				}

				return err
			}

			return nil
		})
	}

	// WrapToPrinter never returns an error, since we don't provide one.
	printer, _ := printers.NewTypeSetter(scheme.Scheme).WrapToPrinter(delegate, nil)
	return printer.PrintObj(obj, out)
}

// writeEventTable writes a html summary of cluster events.
func writeEventTable(events []corev1.Event, out io.Writer) error {
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

	return t.Execute(out, events)
}

func indentAsListItem(in []byte, out io.Writer) (cnt int, err error) {
	handle := func(n int, err error) error {
		cnt += n
		return err
	}

	indent := []byte("- ")
	for len(in) > 0 {
		to := bytes.IndexAny(in, "\n")
		if to == -1 {
			to = len(in)
		} else {
			to++
		}

		if err = handle(out.Write(indent)); err != nil {
			return cnt, err
		}
		if err = handle(out.Write(in[:to])); err != nil {
			return cnt, err
		}

		in, indent = in[to:], []byte("  ")
	}

	return cnt, nil
}
