/*
Copyright 2016 The Kubernetes Authors.

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

package generators

import (
	"io"

	clientgentypes "k8s.io/code-generator/cmd/client-gen/types"
	"k8s.io/gengo/generator"
	"k8s.io/gengo/namer"
	"k8s.io/gengo/types"

	"github.com/golang/glog"
)

// factoryGenerator produces a file of listers for a given GroupVersion and
// type.
type factoryGenerator struct {
	generator.DefaultGen
	outputPackage             string
	imports                   namer.ImportTracker
	groupVersions             map[string]clientgentypes.GroupVersions
	clientSetPackage          string
	internalInterfacesPackage string
	filtered                  bool
}

var _ generator.Generator = &factoryGenerator{}

func (g *factoryGenerator) Filter(c *generator.Context, t *types.Type) bool {
	if !g.filtered {
		g.filtered = true
		return true
	}
	return false
}

func (g *factoryGenerator) Namers(c *generator.Context) namer.NameSystems {
	return namer.NameSystems{
		"raw": namer.NewRawNamer(g.outputPackage, g.imports),
	}
}

func (g *factoryGenerator) Imports(c *generator.Context) (imports []string) {
	imports = append(imports, g.imports.ImportLines()...)
	return
}

func (g *factoryGenerator) GenerateType(c *generator.Context, t *types.Type, w io.Writer) error {
	sw := generator.NewSnippetWriter(w, c, "{{", "}}")

	glog.V(5).Infof("processing type %v", t)

	gvInterfaces := make(map[string]*types.Type)
	gvNewFuncs := make(map[string]*types.Type)
	for groupName := range g.groupVersions {
		gvInterfaces[groupName] = c.Universe.Type(types.Name{Package: packageForGroup(vendorless(g.outputPackage), g.groupVersions[groupName].Group), Name: "Interface"})
		gvNewFuncs[groupName] = c.Universe.Function(types.Name{Package: packageForGroup(vendorless(g.outputPackage), g.groupVersions[groupName].Group), Name: "New"})
	}
	m := map[string]interface{}{
		"cacheSharedIndexInformer":   c.Universe.Type(cacheSharedIndexInformer),
		"groupVersions":              g.groupVersions,
		"gvInterfaces":               gvInterfaces,
		"gvNewFuncs":                 gvNewFuncs,
		"interfacesNewInformerFunc":  c.Universe.Type(types.Name{Package: g.internalInterfacesPackage, Name: "NewInformerFunc"}),
		"informerFactoryInterface":   c.Universe.Type(types.Name{Package: g.internalInterfacesPackage, Name: "SharedInformerFactory"}),
		"clientSetInterface":         c.Universe.Type(types.Name{Package: g.clientSetPackage, Name: "Interface"}),
		"reflectType":                c.Universe.Type(reflectType),
		"runtimeObject":              c.Universe.Type(runtimeObject),
		"schemaGroupVersionResource": c.Universe.Type(schemaGroupVersionResource),
		"syncMutex":                  c.Universe.Type(syncMutex),
		"timeDuration":               c.Universe.Type(timeDuration),
	}

	sw.Do(sharedInformerFactoryStruct, m)
	sw.Do(sharedInformerFactoryInterface, m)

	return sw.Error()
}

var sharedInformerFactoryStruct = `
type sharedInformerFactory struct {
	client {{.clientSetInterface|raw}}
	lock {{.syncMutex|raw}}
	defaultResync {{.timeDuration|raw}}

	informers map[{{.reflectType|raw}}]{{.cacheSharedIndexInformer|raw}}
	// startedInformers is used for tracking which informers have been started.
	// This allows Start() to be called multiple times safely.
	startedInformers map[{{.reflectType|raw}}]bool
}

// NewSharedInformerFactory constructs a new instance of sharedInformerFactory
func NewSharedInformerFactory(client {{.clientSetInterface|raw}}, defaultResync {{.timeDuration|raw}}) SharedInformerFactory {
  return &sharedInformerFactory{
		client: client,
    defaultResync:    defaultResync,
    informers:        make(map[{{.reflectType|raw}}]{{.cacheSharedIndexInformer|raw}}),
    startedInformers: make(map[{{.reflectType|raw}}]bool),
  }
}

// Start initializes all requested informers.
func (f *sharedInformerFactory) Start(stopCh <-chan struct{}) {
  f.lock.Lock()
  defer f.lock.Unlock()

  for informerType, informer := range f.informers {
    if !f.startedInformers[informerType] {
      go informer.Run(stopCh)
      f.startedInformers[informerType] = true
    }
  }
}

// WaitForCacheSync waits for all started informers' cache were synced.
func (f *sharedInformerFactory) WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool {
	informers := func()map[reflect.Type]cache.SharedIndexInformer{
               f.lock.Lock()
               defer f.lock.Unlock()

               informers := map[reflect.Type]cache.SharedIndexInformer{}
               for informerType, informer := range f.informers {
                       if f.startedInformers[informerType] {
                               informers[informerType] = informer
                       }
               }
               return informers
       }()

       res := map[reflect.Type]bool{}
       for informType, informer := range informers {
               res[informType] = cache.WaitForCacheSync(stopCh, informer.HasSynced)
       }
       return res
}

// InternalInformerFor returns the SharedIndexInformer for obj using an internal
// client.
func (f *sharedInformerFactory) InformerFor(obj {{.runtimeObject|raw}}, newFunc {{.interfacesNewInformerFunc|raw}}) {{.cacheSharedIndexInformer|raw}} {
  f.lock.Lock()
  defer f.lock.Unlock()

  informerType := reflect.TypeOf(obj)
  informer, exists := f.informers[informerType]
  if exists {
    return informer
  }
  informer = newFunc(f.client, f.defaultResync)
  f.informers[informerType] = informer

  return informer
}

`

var sharedInformerFactoryInterface = `
// SharedInformerFactory provides shared informers for resources in all known
// API group versions.
type SharedInformerFactory interface {
	{{.informerFactoryInterface|raw}}
	ForResource(resource {{.schemaGroupVersionResource|raw}}) (GenericInformer, error)
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool

	{{$gvInterfaces := .gvInterfaces}}
	{{range $groupName, $group := .groupVersions}}{{$groupName}}() {{index $gvInterfaces $groupName|raw}}
	{{end}}
}

{{$gvNewFuncs := .gvNewFuncs}}
{{range $groupName, $group := .groupVersions}}
func (f *sharedInformerFactory) {{$groupName}}() {{index $gvInterfaces $groupName|raw}} {
  return {{index $gvNewFuncs $groupName|raw}}(f)
}
{{end}}
`
