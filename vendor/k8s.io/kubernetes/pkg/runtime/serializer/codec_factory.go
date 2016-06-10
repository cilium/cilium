/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package serializer

import (
	"io"

	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/runtime/serializer/json"
	"k8s.io/kubernetes/pkg/runtime/serializer/recognizer"
	"k8s.io/kubernetes/pkg/runtime/serializer/versioning"
)

// serializerExtensions are for serializers that are conditionally compiled in
var serializerExtensions = []func(*runtime.Scheme) (serializerType, bool){}

type serializerType struct {
	AcceptContentTypes []string
	ContentType        string
	FileExtensions     []string
	// EncodesAsText should be true if this content type can be represented safely in UTF-8
	EncodesAsText bool

	Serializer       runtime.Serializer
	PrettySerializer runtime.Serializer
	// RawSerializer serializes an object without adding a type wrapper. Some serializers, like JSON
	// automatically include identifying type information with the JSON. Others, like Protobuf, need
	// a wrapper object that includes type information. This serializer should be set if the serializer
	// can serialize / deserialize objects without type info. Note that this serializer will always
	// be expected to pass into or a gvk to Decode, since no type information will be available on
	// the object itself.
	RawSerializer runtime.Serializer
	// Specialize gives the type the opportunity to return a different serializer implementation if
	// the content type contains alternate operations. Here it is used to implement "pretty" as an
	// option to application/json, but could also be used to allow serializers to perform type
	// defaulting or alter output.
	Specialize func(map[string]string) (runtime.Serializer, bool)

	AcceptStreamContentTypes []string
	StreamContentType        string

	Framer           runtime.Framer
	StreamSerializer runtime.Serializer
	StreamSpecialize func(map[string]string) (runtime.Serializer, bool)
}

func newSerializersForScheme(scheme *runtime.Scheme, mf json.MetaFactory) []serializerType {
	jsonSerializer := json.NewSerializer(mf, scheme, scheme, false)
	jsonPrettySerializer := json.NewSerializer(mf, scheme, scheme, true)
	yamlSerializer := json.NewYAMLSerializer(mf, scheme, scheme)

	serializers := []serializerType{
		{
			AcceptContentTypes: []string{"application/json"},
			ContentType:        "application/json",
			FileExtensions:     []string{"json"},
			EncodesAsText:      true,
			Serializer:         jsonSerializer,
			PrettySerializer:   jsonPrettySerializer,

			AcceptStreamContentTypes: []string{"application/json", "application/json;stream=watch"},
			StreamContentType:        "application/json",
			Framer:                   json.Framer,
			StreamSerializer:         jsonSerializer,
		},
		{
			AcceptContentTypes: []string{"application/yaml"},
			ContentType:        "application/yaml",
			FileExtensions:     []string{"yaml"},
			EncodesAsText:      true,
			Serializer:         yamlSerializer,

			// TODO: requires runtime.RawExtension to properly distinguish when the nested content is
			// yaml, because the yaml encoder invokes MarshalJSON first
			//AcceptStreamContentTypes: []string{"application/yaml", "application/yaml;stream=watch"},
			//StreamContentType:        "application/yaml;stream=watch",
			//Framer:                   json.YAMLFramer,
			//StreamSerializer:         yamlSerializer,
		},
	}

	for _, fn := range serializerExtensions {
		if serializer, ok := fn(scheme); ok {
			serializers = append(serializers, serializer)
		}
	}
	return serializers
}

// CodecFactory provides methods for retrieving codecs and serializers for specific
// versions and content types.
type CodecFactory struct {
	scheme           *runtime.Scheme
	serializers      []serializerType
	universal        runtime.Decoder
	accepts          []string
	streamingAccepts []string

	legacySerializer runtime.Serializer
}

// NewCodecFactory provides methods for retrieving serializers for the supported wire formats
// and conversion wrappers to define preferred internal and external versions. In the future,
// as the internal version is used less, callers may instead use a defaulting serializer and
// only convert objects which are shared internally (Status, common API machinery).
// TODO: allow other codecs to be compiled in?
// TODO: accept a scheme interface
func NewCodecFactory(scheme *runtime.Scheme) CodecFactory {
	serializers := newSerializersForScheme(scheme, json.DefaultMetaFactory)
	return newCodecFactory(scheme, serializers)
}

// newCodecFactory is a helper for testing that allows a different metafactory to be specified.
func newCodecFactory(scheme *runtime.Scheme, serializers []serializerType) CodecFactory {
	decoders := make([]runtime.Decoder, 0, len(serializers))
	accepts := []string{}
	alreadyAccepted := make(map[string]struct{})

	var legacySerializer runtime.Serializer
	for _, d := range serializers {
		decoders = append(decoders, d.Serializer)
		for _, mediaType := range d.AcceptContentTypes {
			if _, ok := alreadyAccepted[mediaType]; ok {
				continue
			}
			alreadyAccepted[mediaType] = struct{}{}
			accepts = append(accepts, mediaType)
			if mediaType == "application/json" {
				legacySerializer = d.Serializer
			}
		}
	}
	if legacySerializer == nil {
		legacySerializer = serializers[0].Serializer
	}

	streamAccepts := []string{}
	alreadyAccepted = make(map[string]struct{})
	for _, d := range serializers {
		if len(d.StreamContentType) == 0 {
			continue
		}
		for _, mediaType := range d.AcceptStreamContentTypes {
			if _, ok := alreadyAccepted[mediaType]; ok {
				continue
			}
			alreadyAccepted[mediaType] = struct{}{}
			streamAccepts = append(streamAccepts, mediaType)
		}
	}

	return CodecFactory{
		scheme:      scheme,
		serializers: serializers,
		universal:   recognizer.NewDecoder(decoders...),

		accepts:          accepts,
		streamingAccepts: streamAccepts,

		legacySerializer: legacySerializer,
	}
}

var _ runtime.NegotiatedSerializer = &CodecFactory{}

// SupportedMediaTypes returns the RFC2046 media types that this factory has serializers for.
func (f CodecFactory) SupportedMediaTypes() []string {
	return f.accepts
}

// SupportedStreamingMediaTypes returns the RFC2046 media types that this factory has stream serializers for.
func (f CodecFactory) SupportedStreamingMediaTypes() []string {
	return f.streamingAccepts
}

// LegacyCodec encodes output to a given API version, and decodes output into the internal form from
// any recognized source. The returned codec will always encode output to JSON.
//
// This method is deprecated - clients and servers should negotiate a serializer by mime-type and
// invoke CodecForVersions. Callers that need only to read data should use UniversalDecoder().
func (f CodecFactory) LegacyCodec(version ...unversioned.GroupVersion) runtime.Codec {
	return versioning.NewCodecForScheme(f.scheme, f.legacySerializer, f.universal, version, nil)
}

// UniversalDeserializer can convert any stored data recognized by this factory into a Go object that satisfies
// runtime.Object. It does not perform conversion. It does not perform defaulting.
func (f CodecFactory) UniversalDeserializer() runtime.Decoder {
	return f.universal
}

// UniversalDecoder returns a runtime.Decoder capable of decoding all known API objects in all known formats. Used
// by clients that do not need to encode objects but want to deserialize API objects stored on disk. Only decodes
// objects in groups registered with the scheme. The GroupVersions passed may be used to select alternate
// versions of objects to return - by default, runtime.APIVersionInternal is used. If any versions are specified,
// unrecognized groups will be returned in the version they are encoded as (no conversion). This decoder performs
// defaulting.
//
// TODO: the decoder will eventually be removed in favor of dealing with objects in their versioned form
func (f CodecFactory) UniversalDecoder(versions ...unversioned.GroupVersion) runtime.Decoder {
	return f.CodecForVersions(nil, f.universal, nil, versions)
}

// CodecFor creates a codec with the provided serializer. If an object is decoded and its group is not in the list,
// it will default to runtime.APIVersionInternal. If encode is not specified for an object's group, the object is not
// converted. If encode or decode are nil, no conversion is performed.
func (f CodecFactory) CodecForVersions(encoder runtime.Encoder, decoder runtime.Decoder, encode []unversioned.GroupVersion, decode []unversioned.GroupVersion) runtime.Codec {
	return versioning.NewCodecForScheme(f.scheme, encoder, decoder, encode, decode)
}

// DecoderToVersion returns a decoder that targets the provided group version.
func (f CodecFactory) DecoderToVersion(decoder runtime.Decoder, gv unversioned.GroupVersion) runtime.Decoder {
	return f.CodecForVersions(nil, decoder, nil, []unversioned.GroupVersion{gv})
}

// EncoderForVersion returns an encoder that targets the provided group version.
func (f CodecFactory) EncoderForVersion(encoder runtime.Encoder, gv unversioned.GroupVersion) runtime.Encoder {
	return f.CodecForVersions(encoder, nil, []unversioned.GroupVersion{gv}, nil)
}

// SerializerForMediaType returns a serializer that matches the provided RFC2046 mediaType, or false if no such
// serializer exists
func (f CodecFactory) SerializerForMediaType(mediaType string, params map[string]string) (runtime.SerializerInfo, bool) {
	for _, s := range f.serializers {
		for _, accepted := range s.AcceptContentTypes {
			if accepted == mediaType {
				// specialization abstracts variants to the content type
				if s.Specialize != nil && len(params) > 0 {
					serializer, ok := s.Specialize(params)
					// TODO: return formatted mediaType+params
					return runtime.SerializerInfo{Serializer: serializer, MediaType: s.ContentType, EncodesAsText: s.EncodesAsText}, ok
				}

				// legacy support for ?pretty=1 continues, but this is more formally defined
				if v, ok := params["pretty"]; ok && v == "1" && s.PrettySerializer != nil {
					return runtime.SerializerInfo{Serializer: s.PrettySerializer, MediaType: s.ContentType, EncodesAsText: s.EncodesAsText}, true
				}

				// return the base variant
				return runtime.SerializerInfo{Serializer: s.Serializer, MediaType: s.ContentType, EncodesAsText: s.EncodesAsText}, true
			}
		}
	}
	return runtime.SerializerInfo{}, false
}

// StreamingSerializerForMediaType returns a serializer that matches the provided RFC2046 mediaType, or false if no such
// serializer exists
func (f CodecFactory) StreamingSerializerForMediaType(mediaType string, params map[string]string) (runtime.StreamSerializerInfo, bool) {
	for _, s := range f.serializers {
		for _, accepted := range s.AcceptStreamContentTypes {
			if accepted == mediaType {
				// TODO: accept params
				nested, ok := f.SerializerForMediaType(s.ContentType, nil)
				if !ok {
					panic("no serializer defined for internal content type")
				}

				if s.StreamSpecialize != nil && len(params) > 0 {
					serializer, ok := s.StreamSpecialize(params)
					// TODO: return formatted mediaType+params
					return runtime.StreamSerializerInfo{
						SerializerInfo: runtime.SerializerInfo{
							Serializer:    serializer,
							MediaType:     s.StreamContentType,
							EncodesAsText: s.EncodesAsText,
						},
						Framer:   s.Framer,
						Embedded: nested,
					}, ok
				}

				return runtime.StreamSerializerInfo{
					SerializerInfo: runtime.SerializerInfo{
						Serializer:    s.StreamSerializer,
						MediaType:     s.StreamContentType,
						EncodesAsText: s.EncodesAsText,
					},
					Framer:   s.Framer,
					Embedded: nested,
				}, true
			}
		}
	}
	return runtime.StreamSerializerInfo{}, false
}

// SerializerForFileExtension returns a serializer for the provided extension, or false if no serializer matches.
func (f CodecFactory) SerializerForFileExtension(extension string) (runtime.Serializer, bool) {
	for _, s := range f.serializers {
		for _, ext := range s.FileExtensions {
			if extension == ext {
				return s.Serializer, true
			}
		}
	}
	return nil, false
}

// DirectCodecFactory provides methods for retrieving "DirectCodec"s, which do not do conversion.
type DirectCodecFactory struct {
	CodecFactory
}

// EncoderForVersion returns an encoder that does not do conversion. gv is ignored.
func (f DirectCodecFactory) EncoderForVersion(serializer runtime.Encoder, gv unversioned.GroupVersion) runtime.Encoder {
	return DirectCodec{
		runtime.NewCodec(serializer, nil),
		f.CodecFactory.scheme,
	}
}

// DecoderToVersion returns an decoder that does not do conversion. gv is ignored.
func (f DirectCodecFactory) DecoderToVersion(serializer runtime.Decoder, gv unversioned.GroupVersion) runtime.Decoder {
	return DirectCodec{
		runtime.NewCodec(nil, serializer),
		nil,
	}
}

// DirectCodec is a codec that does not do conversion. It sets the gvk during serialization, and removes the gvk during deserialization.
type DirectCodec struct {
	runtime.Serializer
	runtime.ObjectTyper
}

// EncodeToStream does not do conversion. It sets the gvk during serialization. overrides are ignored.
func (c DirectCodec) EncodeToStream(obj runtime.Object, stream io.Writer, overrides ...unversioned.GroupVersion) error {
	gvks, _, err := c.ObjectTyper.ObjectKinds(obj)
	if err != nil {
		return err
	}
	kind := obj.GetObjectKind()
	oldGVK := kind.GroupVersionKind()
	kind.SetGroupVersionKind(gvks[0])
	err = c.Serializer.EncodeToStream(obj, stream, overrides...)
	kind.SetGroupVersionKind(oldGVK)
	return err
}

// Decode does not do conversion. It removes the gvk during deserialization.
func (c DirectCodec) Decode(data []byte, defaults *unversioned.GroupVersionKind, into runtime.Object) (runtime.Object, *unversioned.GroupVersionKind, error) {
	obj, gvk, err := c.Serializer.Decode(data, defaults, into)
	if obj != nil {
		kind := obj.GetObjectKind()
		// clearing the gvk is just a convention of a codec
		kind.SetGroupVersionKind(unversioned.GroupVersionKind{})
	}
	return obj, gvk, err
}
