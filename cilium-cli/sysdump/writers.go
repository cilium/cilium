// Copyright 2021 Authors of Cilium
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

package sysdump

import (
	"bytes"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes/scheme"
)

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
