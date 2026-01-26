// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/testing"
	"k8s.io/client-go/util/jsonpath"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	logfieldGVR               = "gvr" //  GroupVersIonResource
	logfieldClientset         = "clientset"
	logfieldResourceVersion   = "resourceVersion"
	logfieldFieldSelector     = "fieldSelector"
	logfieldSendInitialEvents = "sendInitialEvents"
)

// statedbObjectTracker implements [testing.ObjectTracker] using a StateDB table.
// This allows for proper implementation of Watch() that respects the ResourceVersion
// allowing multiple Watch() calls in parallel.
//
// This object tracker is prepended to the reactor chain and will process the objects
// and short-circuit the chain before the fake client's own object tracker.
//
// https://pkg.go.dev/k8s.io/client-go/testing#ObjectTracker
type statedbObjectTracker struct {
	domain  string
	log     *slog.Logger
	db      *statedb.DB
	scheme  *runtime.Scheme
	decoder runtime.Decoder
	tbl     statedb.RWTable[object]
}

func newStateDBObjectTracker(db *statedb.DB, log *slog.Logger) (*statedbObjectTracker, error) {
	tbl, err := statedb.NewTable(db, "k8s-object-tracker", objectIndex)
	if err != nil {
		return nil, err
	}
	return &statedbObjectTracker{
		log:     log,
		db:      db,
		tbl:     tbl,
		scheme:  testutils.Scheme,
		decoder: testutils.Decoder(),
	}, nil
}

type object struct {
	objectId
	kind    string
	deleted bool
	o       runtime.Object
}

func (o object) TableHeader() []string {
	return []string{
		"ID",
		"Deleted",
		"Type",
	}
}

func (o object) TableRow() []string {
	return []string{
		o.objectId.String(),
		fmt.Sprintf("%v", o.deleted),
		fmt.Sprintf("%T", o.o),
	}
}

type objectId struct {
	types.NamespacedName
	gvr schema.GroupVersionResource

	// domain to which this objects belongs, e.g. this is used
	// to differentiate between the slim and kubernetes clientsets
	// and avoid mixing them up since they have the same [gvr]
	domain string
}

func newObjectId(clientset string, gvr schema.GroupVersionResource, namespace, name string) (o objectId) {
	o.domain = clientset
	o.gvr = gvr
	o.Namespace = namespace
	o.Name = name
	return
}

func (oid objectId) String() string {
	return oid.domain + ";" + oid.gvr.String() + ";" + oid.NamespacedName.String()
}

func (oid objectId) Key() index.Key {
	return index.Stringer(oid)
}

var (
	objectIndex = statedb.Index[object, objectId]{
		Name: "id",
		FromObject: func(obj object) index.KeySet {
			return index.NewKeySet(obj.Key())
		},
		FromKey: index.Stringer[objectId],
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}
)

type gvrk struct {
	schema.GroupVersionResource
	kind string
}

func (g gvrk) groupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   g.Group,
		Version: g.Version,
		Kind:    g.kind,
	}
}

func (s *statedbObjectTracker) getGVRKs() iter.Seq[gvrk] {
	rs := container.NewInsertOrderedMap[schema.GroupVersionResource, gvrk]()
	for obj := range s.tbl.All(s.db.ReadTxn()) {
		rs.Insert(obj.gvr, gvrk{
			GroupVersionResource: obj.gvr,
			kind:                 obj.kind,
		})
	}
	return rs.Values()
}

// For returns a object tracker for a specific use-case (domain) that is separate from others.
func (s *statedbObjectTracker) For(domain string, scheme *runtime.Scheme, decoder runtime.Decoder) *statedbObjectTracker {
	o := *s
	o.domain = domain
	o.scheme = scheme
	o.decoder = decoder
	return &o
}

func (s *statedbObjectTracker) ObjectReaction() testing.ReactionFunc {
	return testing.ObjectReaction(s)
}

func (s *statedbObjectTracker) addList(obj runtime.Object) error {
	list, err := meta.ExtractList(obj)
	if err != nil {
		return err
	}
	errs := runtime.DecodeList(list, s.decoder)
	if len(errs) > 0 {
		return errs[0]
	}
	for _, obj := range list {
		if err := s.Add(obj); err != nil {
			return err
		}
	}
	return nil
}

// fillTypeMetaIfNeeded sets the [metav1.TypeMeta] in the object if it's not already set based
// on the GroupVersionKind found from the schema.
func fillTypeMetaIfNeeded(obj runtime.Object, gvk schema.GroupVersionKind) runtime.Object {
	if obj.GetObjectKind().GroupVersionKind().Empty() {
		obj = obj.DeepCopyObject()
		obj.GetObjectKind().SetGroupVersionKind(gvk)
	}
	return obj
}

// Add adds an object to the tracker. If object being added
// is a list, its items are added separately.
func (s *statedbObjectTracker) Add(obj runtime.Object) error {
	if meta.IsListType(obj) {
		return s.addList(obj)
	}

	wtxn := s.db.WriteTxn(s.tbl)
	defer wtxn.Commit()

	obj = obj.DeepCopyObject()
	objMeta, err := meta.Accessor(obj)
	if err != nil {
		s.log.Debug("Add", logfields.Error, err)
		return err
	}

	version := s.tbl.Revision(wtxn) + 1
	objMeta.SetResourceVersion(strconv.FormatUint(version, 10))

	gvks, _, err := s.scheme.ObjectKinds(obj)
	if err != nil {
		s.log.Debug("Add", logfields.Error, err)
		return err
	}

	if len(gvks) == 0 {
		err := fmt.Errorf("no registered kinds for %v", obj)
		s.log.Debug("Add", logfields.Error, err)
		return err
	}

	for _, gvk := range gvks {
		// NOTE: UnsafeGuessKindToResource is a heuristic and default match. The
		// actual registration in apiserver can specify arbitrary route for a
		// gvk. If a test uses such objects, it cannot preset the tracker with
		// objects via Add(). Instead, it should trigger the Create() function
		// of the tracker, where an arbitrary gvr can be specified.
		gvr, _ := meta.UnsafeGuessKindToResource(gvk)
		// Resource doesn't have the concept of "__internal" version, just set it to "".
		if gvr.Version == runtime.APIVersionInternal {
			gvr.Version = ""
		}

		obj = fillTypeMetaIfNeeded(obj, gvk)

		s.log.Debug(
			"Add",
			logfieldClientset, s.domain,
			logfieldGVR, gvr,
			logfields.K8sNamespace, objMeta.GetNamespace(),
			logfields.Name, objMeta.GetName(),
		)

		s.tbl.Insert(wtxn, object{
			objectId: newObjectId(s.domain, gvr, objMeta.GetNamespace(), objMeta.GetName()),
			o:        obj,
			kind:     gvk.Kind,
		})
	}
	return nil
}

// Apply applies an object in the tracker in the specified namespace.
func (s *statedbObjectTracker) Apply(gvr schema.GroupVersionResource, applyConfiguration runtime.Object, ns string, opts ...metav1.PatchOptions) error {
	log := s.log.With(
		logfieldClientset, s.domain,
		logfields.Object, applyConfiguration)

	applyConfigurationMeta, err := meta.Accessor(applyConfiguration)
	if err != nil {
		log.Debug("Apply", logfields.Error, err)
		return err
	}

	obj, err := s.Get(gvr, ns, applyConfigurationMeta.GetName(), metav1.GetOptions{})
	if err != nil {
		log.Debug("Apply", logfields.Error, err)
		return err
	}

	old, err := json.Marshal(obj)
	if err != nil {
		log.Debug("Apply", logfields.Error, err)
		return err
	}

	// reset the object in preparation to unmarshal, since unmarshal does not guarantee that fields
	// in obj that are removed by patch are cleared
	value := reflect.ValueOf(obj)
	value.Elem().Set(reflect.New(value.Type().Elem()).Elem())

	// For backward compatibility with behavior 1.30 and earlier, continue to handle apply
	// via strategic merge patch (clients may use fake.NewClientset and ManagedFieldObjectTracker
	// for full field manager support).
	patch, err := json.Marshal(applyConfiguration)
	if err != nil {
		log.Debug("Apply", logfields.Error, err)
		return err
	}
	mergedByte, err := strategicpatch.StrategicMergePatch(old, patch, obj)
	if err != nil {
		log.Debug("Apply", logfields.Error, err)
		return err
	}
	if err = json.Unmarshal(mergedByte, obj); err != nil {
		log.Debug("Apply", logfields.Error, err)
		return err
	}

	err = s.Update(gvr, obj, ns)
	s.log.Debug("Apply", logfields.Error, err)
	return err
}

// Create adds an object to the tracker in the specified namespace. If the object exists an error is returned.
func (s *statedbObjectTracker) Create(gvr schema.GroupVersionResource, obj runtime.Object, ns string, opts ...metav1.CreateOptions) error {
	log := s.log.With(
		logfieldClientset, s.domain,
		logfields.Object, obj)

	gvks, _, err := s.scheme.ObjectKinds(obj)
	if err != nil {
		s.log.Debug("Create", logfields.Error, err)
		return err
	}
	if len(gvks) == 0 {
		err = fmt.Errorf("no kind found for %+v", gvr)
		s.log.Debug("Create", logfields.Error, err)
		return err
	}
	gvk := gvks[0]

	obj = obj.DeepCopyObject()
	newMeta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	if len(newMeta.GetNamespace()) == 0 {
		newMeta.SetNamespace(ns)
	}

	obj = fillTypeMetaIfNeeded(obj, gvks[0])

	wtxn := s.db.WriteTxn(s.tbl)
	version := s.tbl.Revision(wtxn) + 1
	newMeta.SetResourceVersion(strconv.FormatUint(version, 10))
	old, found, _ := s.tbl.Insert(wtxn, object{
		objectId: newObjectId(s.domain, gvr, ns, newMeta.GetName()),
		o:        obj,
		kind:     gvk.Kind,
	})
	if found && !old.deleted {
		wtxn.Abort()
		gr := gvr.GroupResource()
		err := apierrors.NewAlreadyExists(gr, newMeta.GetName())
		log.Debug("Create", logfields.Error, err)
		return err
	}
	log.Debug("Create")
	wtxn.Commit()
	return nil
}

// Delete deletes an existing object from the tracker. If object
// didn't exist in the tracker prior to deletion, Delete returns
// no error.
func (s *statedbObjectTracker) Delete(gvr schema.GroupVersionResource, ns string, name string, opts ...metav1.DeleteOptions) error {
	log := s.log.With(
		logfieldClientset, s.domain,
		logfields.K8sNamespace, ns,
		logfields.Name, name)

	wtxn := s.db.WriteTxn(s.tbl)
	obj, _, found := s.tbl.Get(wtxn, objectIndex.Query(newObjectId(s.domain, gvr, ns, name)))
	if found {
		obj.deleted = true
		s.tbl.Insert(wtxn, obj)
	} else {
		wtxn.Abort()
		err := apierrors.NewNotFound(gvr.GroupResource(), name)
		log.Debug("Delete", logfields.Error, err)
		return err
	}
	wtxn.Commit()
	log.Debug("Delete")
	return nil
}

// Get retrieves the object by its kind, namespace and name.
// Returns an error if object is not found.
func (s *statedbObjectTracker) Get(gvr schema.GroupVersionResource, ns string, name string, opts ...metav1.GetOptions) (runtime.Object, error) {
	log := s.log.With(
		logfieldClientset, s.domain,
		logfieldGVR, gvr,
		logfields.K8sNamespace, ns,
		logfields.Name, name)

	txn := s.db.ReadTxn()
	obj, rev, found := s.tbl.Get(txn, objectIndex.Query(newObjectId(s.domain, gvr, ns, name)))
	if !found || obj.deleted {
		err := apierrors.NewNotFound(gvr.GroupResource(), name)
		log.Debug("Get", logfields.Error, err)
		return nil, err
	}
	log.Debug("Get", logfieldResourceVersion, rev)
	return obj.o.DeepCopyObject(), nil
}

// List retrieves all objects of a given kind in the given
// namespace. Only non-List kinds are accepted.
func (s *statedbObjectTracker) List(gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, ns string, opts ...metav1.ListOptions) (runtime.Object, error) {
	// Heuristic for list kind: original kind + List suffix. Might
	// not always be true but this tracker has a pretty limited
	// understanding of the actual API model.
	listGVK := gvk
	listGVK.Kind = listGVK.Kind + "List"
	// GVK does have the concept of "internal version". The scheme recognizes
	// the runtime.APIVersionInternal, but not the empty string.
	if listGVK.Version == "" {
		listGVK.Version = runtime.APIVersionInternal
	}

	list, err := s.scheme.New(listGVK)
	if err != nil {
		list, err = testutils.KubernetesScheme.New(listGVK)
	}
	if err != nil {
		return nil, err
	}

	if !meta.IsListType(list) {
		return nil, fmt.Errorf("%q is not a list type", listGVK.Kind)
	}

	var fieldSelector fields.Selector
	if len(opts) > 0 {
		opt := opts[0]
		if opt.FieldSelector != "" {
			fieldSelector, err = fields.ParseSelector(opt.FieldSelector)
			if err != nil {
				return nil, err
			}
		}
	}

	matchingObjects := []runtime.Object{}
	txn := s.db.ReadTxn()

	for obj := range s.tbl.All(txn) {
		if obj.deleted {
			continue
		}
		if obj.domain != s.domain || obj.gvr != gvr ||
			(ns != "" && obj.Namespace != ns) {
			continue
		}

		if fieldSelector != nil {
			if !objectMatchesFieldSelector(obj.o, fieldSelector) {
				s.log.Debug("List: Skipping object due to FieldSelector mismatch",
					logfields.K8sNamespace, ns,
					logfields.Name, obj.Name,
					logfieldFieldSelector, fieldSelector)
				continue
			}
		}

		matchingObjects = append(matchingObjects, obj.o.DeepCopyObject())
	}
	m, _ := meta.ListAccessor(list)
	m.SetResourceVersion(strconv.FormatUint(s.tbl.Revision(txn), 10))

	if err := meta.SetList(list, matchingObjects); err != nil {
		return nil, err
	}

	s.log.Debug(
		"List",
		logfieldClientset, s.domain,
		logfieldGVR, gvr,
		logfields.K8sNamespace, ns,
		logfields.Count, len(matchingObjects),
		logfields.Version, m.GetResourceVersion(),
	)
	return list, nil
}

// Patch patches an existing object in the tracker in the specified namespace.
//
// The reactor functions take care of actually processing the patch
// (objectTrackerReact.Patch in client-go/testing/fixture.go).
func (s *statedbObjectTracker) Patch(gvr schema.GroupVersionResource, obj runtime.Object, ns string, opts ...metav1.PatchOptions) error {
	return s.updateOrPatch("Patch", gvr, obj, ns)
}

// Update updates an existing object in the tracker in the specified namespace.
// If the object does not exist an error is returned.
func (s *statedbObjectTracker) Update(gvr schema.GroupVersionResource, obj runtime.Object, ns string, opts ...metav1.UpdateOptions) error {
	return s.updateOrPatch("Update", gvr, obj, ns)
}

func (s *statedbObjectTracker) updateOrPatch(what string, gvr schema.GroupVersionResource, obj runtime.Object, ns string, opts ...metav1.UpdateOptions) error {
	gvks, _, err := s.scheme.ObjectKinds(obj)
	if err != nil {
		s.log.Debug(what, logfields.Error, err)
		return err
	}
	if len(gvks) == 0 {
		err = fmt.Errorf("no kind found for %+v", gvr)
		s.log.Debug(what, logfields.Error, err)
		return err
	}
	gvk := gvks[0]

	obj = obj.DeepCopyObject()
	newMeta, err := meta.Accessor(obj)
	if err != nil {
		s.log.Debug(what, logfields.Error, err)
		return err
	}
	if len(newMeta.GetNamespace()) == 0 {
		newMeta.SetNamespace(ns)
	}

	obj = fillTypeMetaIfNeeded(obj, gvks[0])

	wtxn := s.db.WriteTxn(s.tbl)
	version := s.tbl.Revision(wtxn) + 1
	newMeta.SetResourceVersion(strconv.FormatUint(version, 10))

	log := s.log.With(
		logfieldClientset, s.domain,
		logfields.Object, obj,
		logfieldResourceVersion, version)

	oldObj, found, _ := s.tbl.Insert(wtxn,
		object{objectId: newObjectId(s.domain, gvr, ns, newMeta.GetName()), o: obj, kind: gvk.Kind},
	)
	if !found || oldObj.deleted {
		wtxn.Abort()
		gr := gvr.GroupResource()
		err := apierrors.NewNotFound(gr, newMeta.GetName())
		log.Debug(what, logfields.Error, err)
		return err
	}
	wtxn.Commit()
	log.Debug(what)
	return nil
}

// Watch watches objects from the tracker. Watch returns a channel
// which will push added / modified / deleted object.
// If SendInitialEvents is set in opts, it will first send Added events for all
// existing objects and then a Bookmark event with the InitialEventsAnnotationKey
// annotation to signal the end of the initial events stream (WatchList semantics).
func (s *statedbObjectTracker) Watch(gvr schema.GroupVersionResource, ns string, opts ...metav1.ListOptions) (watch.Interface, error) {
	var fieldSelector fields.Selector
	var err error
	var sendInitialEvents bool
	version := uint64(0)
	if len(opts) > 0 {
		opt := opts[0]
		if opt.ResourceVersion != "" {
			version, err = strconv.ParseUint(opt.ResourceVersion, 10, 64)
			if err != nil {
				return nil, err
			}
		}

		if opt.FieldSelector != "" {
			fieldSelector, err = fields.ParseSelector(opt.FieldSelector)
			if err != nil {
				return nil, err
			}
		}

		// WatchList semantics: if SendInitialEvents is true, we need to send
		// Added events for all existing objects, followed by a Bookmark event.
		if opt.SendInitialEvents != nil && *opt.SendInitialEvents {
			sendInitialEvents = true
		}
	}

	s.log.Debug("Watch",
		logfieldClientset, s.domain,
		logfieldGVR, gvr,
		logfields.K8sNamespace, ns,
		logfieldResourceVersion, version,
		logfieldSendInitialEvents, sendInitialEvents)

	// Look up Kind from an existing object with this GVR
	var kind string
	for obj := range s.tbl.All(s.db.ReadTxn()) {
		if obj.domain == s.domain && obj.gvr == gvr {
			kind = obj.kind
			break
		}
	}

	w := &statedbWatch{
		clientset:         s.domain,
		scheme:            s.scheme,
		tbl:               s.tbl,
		log:               s.log,
		version:           version,
		gvr:               gvr,
		kind:              kind,
		ns:                ns,
		db:                s.db,
		stop:              make(chan struct{}),
		stopped:           make(chan struct{}),
		events:            make(chan watch.Event, 1),
		fieldSelector:     fieldSelector,
		sendInitialEvents: sendInitialEvents,
	}
	go w.feed()

	return w, nil
}

type statedbWatch struct {
	clientset         string
	scheme            *runtime.Scheme
	tbl               statedb.Table[object]
	log               *slog.Logger
	gvr               schema.GroupVersionResource
	kind              string // Kind for creating bookmark objects, looked up at watch creation
	ns                string
	version           statedb.Revision
	db                *statedb.DB
	stop              chan struct{}
	stopOnce          sync.Once
	stopped           chan struct{}
	events            chan watch.Event
	fieldSelector     fields.Selector
	sendInitialEvents bool
}

// ResultChan implements watch.Interface.
func (w *statedbWatch) ResultChan() <-chan watch.Event {
	return w.events
}

func (w *statedbWatch) feed() {
	defer close(w.stopped)
	defer close(w.events)
	seen := sets.New[string]()
	lastRev := w.version

	// WatchList semantics: if sendInitialEvents is true, first send Added events
	// for all existing objects, then send a Bookmark event to signal the end of
	// initial events.
	if w.sendInitialEvents {
		txn := w.db.ReadTxn()
		for obj := range w.tbl.All(txn) {
			if obj.deleted {
				continue
			}
			if obj.domain != w.clientset {
				continue
			}
			if (w.ns != "" && obj.Namespace != w.ns) || obj.gvr != w.gvr {
				continue
			}

			if w.fieldSelector != nil {
				if !objectMatchesFieldSelector(obj.o, w.fieldSelector) {
					continue
				}
			}

			ev := watch.Event{
				Type:   watch.Added,
				Object: obj.o.DeepCopyObject(),
			}
			seen.Insert(obj.Name)

			w.log.Debug(
				"InitialEvent",
				logfieldGVR, obj.gvr,
				logfields.K8sNamespace, obj.Namespace,
				logfields.Name, obj.Name,
				logfields.Type, ev.Type,
			)

			select {
			case w.events <- ev:
			case <-w.stop:
				return
			}
		}

		// Update lastRev to current revision so we don't re-send these objects
		lastRev = w.tbl.Revision(txn)

		// Send the bookmark event to signal end of initial events
		ev := watch.Event{
			Type:   watch.Bookmark,
			Object: w.createBookmarkObject(lastRev),
		}
		w.log.Debug("SendingBookmark", logfieldResourceVersion, lastRev)
		select {
		case w.events <- ev:
		case <-w.stop:
			return
		}
	}

	for {
		objs, objsWatch := w.tbl.LowerBoundWatch(w.db.ReadTxn(), statedb.ByRevision[object](lastRev+1))
		for obj, rev := range objs {
			lastRev = rev
			if obj.domain != w.clientset {
				continue
			}
			if (w.ns != "" && obj.Namespace != w.ns) || obj.gvr != w.gvr {
				continue
			}

			if w.fieldSelector != nil {
				if !objectMatchesFieldSelector(obj.o, w.fieldSelector) {
					w.log.Debug("Watch: Skipping event due to FieldSelector mismatch",
						logfieldFieldSelector, w.fieldSelector)
					continue
				}
			}

			var ev watch.Event
			ev.Object = obj.o.DeepCopyObject()

			switch {
			case obj.deleted:
				ev.Type = watch.Deleted
				seen.Delete(obj.Name)
			case seen.Has(obj.Name):
				ev.Type = watch.Modified
			default:
				ev.Type = watch.Added
				seen.Insert(obj.Name)
			}
			w.log.Debug(
				"Event",
				logfieldGVR, obj.gvr,
				logfields.K8sNamespace, obj.Namespace,
				logfields.Name, obj.Name,
				logfields.Type, ev.Type,
				logfieldResourceVersion, rev,
				logfields.Object, ev.Object,
			)
			select {
			case w.events <- ev:
			case <-w.stop:
				return
			}
		}
		select {
		case <-w.stop:
			return
		case <-objsWatch:
		}
	}
}

// createBookmarkObject creates a minimal object with the InitialEventsAnnotationKey
// annotation set to "true" to signal the end of initial events in WatchList mode.
// The bookmark must be of the correct type because the reflector validates event types
// and skips events with mismatched types.
func (w *statedbWatch) createBookmarkObject(resourceVersion statedb.Revision) runtime.Object {
	kind := w.kind
	if kind == "" {
		// Fallback to guessing if no objects exist for this GVR
		kind = w.guessKindFromResource(w.gvr)
	}

	gvk := w.gvr.GroupVersion().WithKind(kind)
	obj, err := w.scheme.New(gvk)
	if err != nil {
		// Fallback: use PartialObjectMetadata
		return &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: w.gvr.GroupVersion().String(),
				Kind:       kind,
			},
			ObjectMeta: metav1.ObjectMeta{
				Annotations:     map[string]string{metav1.InitialEventsAnnotationKey: "true"},
				ResourceVersion: strconv.FormatUint(resourceVersion, 10),
			},
		}
	}

	obj.GetObjectKind().SetGroupVersionKind(gvk)
	objMeta, _ := meta.Accessor(obj)
	objMeta.SetAnnotations(map[string]string{metav1.InitialEventsAnnotationKey: "true"})
	objMeta.SetResourceVersion(strconv.FormatUint(resourceVersion, 10))
	return obj
}

// guessKindFromResource attempts to guess the Kind from the resource name using the scheme.
// It uses meta.UnsafeGuessKindToResource in reverse by iterating over all known types.
// e.g., "ciliumnodes" -> "CiliumNode", "services" -> "Service"
func (w *statedbWatch) guessKindFromResource(gvr schema.GroupVersionResource) string {
	// Build a mapping from resource to kind using all known types in the scheme
	// We use UnsafeGuessKindToResource to convert each known GVK to its resource name,
	// then look up our GVR in that mapping.
	for gvk := range w.scheme.AllKnownTypes() {
		if gvk.Group != gvr.Group || gvk.Version != gvr.Version {
			continue
		}
		// Use the same logic k8s uses to convert Kind to resource
		plural, _ := meta.UnsafeGuessKindToResource(gvk)
		if plural.Resource == gvr.Resource {
			return gvk.Kind
		}
	}

	// Fallback: just capitalize the first letter of the singular resource name
	resource := gvr.Resource
	singular := resource
	if strings.HasSuffix(resource, "ies") {
		singular = resource[:len(resource)-3] + "y"
	} else if strings.HasSuffix(resource, "ses") || strings.HasSuffix(resource, "xes") {
		singular = resource[:len(resource)-2]
	} else if strings.HasSuffix(resource, "s") {
		singular = resource[:len(resource)-1]
	}
	if len(singular) == 0 {
		return singular
	}
	return strings.ToUpper(singular[:1]) + singular[1:]
}

// Stop implements watch.Interface.
func (w *statedbWatch) Stop() {
	w.stopOnce.Do(func() {
		close(w.stop)
	})
	<-w.stopped
}

var _ watch.Interface = &statedbWatch{}

var _ testing.ObjectTracker = &statedbObjectTracker{}

func objectMatchesFieldSelector(obj runtime.Object, sel fields.Selector) bool {
	for _, req := range sel.Requirements() {
		value, err := getFieldPathValue(obj, req.Field)
		if err != nil {
			return false
		}
		// https://kubernetes.io/docs/concepts/overview/working-with-objects/field-selectors/#supported-operators
		// Only =, == and != are supported.
		switch req.Operator {
		case selection.DoubleEquals, selection.Equals:
			if value != req.Value {
				return false
			}
		case selection.NotEquals:
			if value == req.Value {
				return false
			}
		default:
			panic(fmt.Sprintf("unsupported operator: %q", req.Operator))
		}
	}
	return true
}

func getFieldPathValue(obj any, fieldPath string) (string, error) {
	p := jsonpath.New("").AllowMissingKeys(false)
	if err := p.Parse("{$." + fieldPath + "}"); err != nil {
		return "", err
	}
	var b strings.Builder
	if err := p.Execute(&b, obj); err != nil {
		return "", err
	}
	return b.String(), nil
}
