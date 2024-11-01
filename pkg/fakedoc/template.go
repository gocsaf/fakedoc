// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import (
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Template describes the structure of the CSAF document to generate
type Template struct {
	// Types maps type names to the corresponding template node
	Types map[string]TmplNode

	// The type of the root node
	Root string
}

// Write writes the template in TOML format
func (t *Template) Write(out io.Writer) error {
	types := make(map[string]map[string]any)
	for name, child := range t.Types {
		types[name] = child.AsMap()
	}
	m := map[string]any{
		"types": types,
		"root":  t.Root,
	}
	return toml.NewEncoder(out).Encode(m)
}

// TmplNode is the interface for template nodes.
type TmplNode interface {
	// AsMap returns a map describing the node for the TOML file
	AsMap() map[string]any
}

// TmplObject describes a JSON object
type TmplObject struct {
	// Properties contains the names of the properties and their
	// corresponding type
	Properties map[string]string `toml:"properties"`

	Probabilities map[string]float32 `toml:"probabilities"`
}

// AsMap implements TmplNode
func (to *TmplObject) AsMap() map[string]any {
	return map[string]any{
		"type":          "object",
		"properties":    to.Properties,
		"probabilities": to.Probabilities,
	}
}

// TmplArray describes a JSON array
type TmplArray struct {
	// Items is the type of the array items
	Items string `toml:"items"`

	// MinItems is the minimum length of the generated array
	MinItems int `toml:"minitems"`
	// MaxLength is the maximum length of the generated array
	MaxItems int `toml:"maxitems"`
}

// AsMap implements TmplNode
func (ta *TmplArray) AsMap() map[string]any {
	return map[string]any{
		"type":     "array",
		"items":    ta.Items,
		"minitems": ta.MinItems,
		"maxitems": ta.MaxItems,
	}
}

// TmplOneOf describes the choice between multiple types
type TmplOneOf struct {
	// OneOf contains the types between which to choose
	OneOf []string `toml:"oneof"`
}

// AsMap implements TmplNode
func (ta *TmplOneOf) AsMap() map[string]any {
	return map[string]any{
		"type":  "oneof",
		"oneof": ta.OneOf,
	}
}

// TmplString describes how to generate strings
type TmplString struct {
	// MinLength is the minimum length of the generated strings
	MinLength int `toml:"minlength"`
	// MaxLength is the maximum length of the generated strings
	MaxLength int `toml:"maxlength"`

	// Enum contains the values to choose from.
	Enum []string `toml:"enum"`

	// Which generator to use. For now, this should be "default"
	Generator string `toml:"generator"`
}

// AsMap implements TmplNode
func (ts *TmplString) AsMap() map[string]any {
	return map[string]any{
		"type":      "string",
		"minlength": ts.MinLength,
		"maxlength": ts.MaxLength,
		"enum":      ts.Enum,
		"generator": ts.Generator,
	}
}

// TmplNumber describes how to generate numbers
type TmplNumber struct {
	// Which generator to use. For now, this should be "default"
	Generator string `toml:"generator"`
}

// AsMap implements TmplNode
func (ts *TmplNumber) AsMap() map[string]any {
	return map[string]any{
		"type":      "number",
		"generator": ts.Generator,
	}
}

// FromSchema creates a default template from a JSON schema.
func FromSchema(schema *jsonschema.Schema) (*Template, error) {
	template := &Template{
		Types: make(map[string]TmplNode),
		Root:  ShortLocation(schema),
	}
	if err := template.fromSchema(schema); err != nil {
		return nil, err
	}
	return template, nil
}

func (t *Template) fromSchema(schema *jsonschema.Schema) error {
	name := ShortLocation(schema)

	// Check for recursion. If name is already in t.Types, we don't have
	// to do anything. If the associated value is nil, we're currently
	// building the node, otherwise the node has already been
	// contstructed.
	if _, ok := t.Types[name]; ok {
		return nil
	}
	t.Types[name] = nil

	ty, tschema, err := getType(schema)
	if err != nil {
		return err
	}
	switch ty {
	case "object":
		properties := make(map[string]string)
		for propName, prop := range tschema.Properties {
			if err := t.fromSchema(prop); err != nil {
				return err
			}
			properties[propName] = ShortLocation(prop)
		}

		// Preset probabilities for the properties. Required properties
		// have probability 1, others get some fixed smaller value.
		probabilities := map[string]float32{}
		for _, name := range tschema.Required {
			probabilities[name] = 1.0
		}
		for name := range properties {
			_, ok := probabilities[name]
			if !ok {
				probabilities[name] = 0.5
			}
		}
		t.Types[name] = &TmplObject{
			Properties:    properties,
			Probabilities: probabilities,
		}
	case "array":
		if err := t.fromSchema(tschema.Items2020); err != nil {
			return err
		}
		t.Types[name] = &TmplArray{
			Items:    ShortLocation(tschema.Items2020),
			MinItems: tschema.MinItems,
			MaxItems: tschema.MaxItems,
		}
	case "oneof":
		oneof := []string{}
		for _, alternative := range tschema.OneOf {
			if err := t.fromSchema(alternative); err != nil {
				return err
			}
			oneof = append(oneof, ShortLocation(alternative))
		}
		t.Types[name] = &TmplOneOf{OneOf: oneof}
	case "string":
		enum := []string{}
		for _, v := range tschema.Enum {
			enum = append(enum, v.(string))
		}
		t.Types[name] = &TmplString{
			MinLength: tschema.MinLength,
			MaxLength: tschema.MaxLength,
			Enum:      enum,
			Generator: "default",
		}
	case "number":
		t.Types[name] = &TmplNumber{Generator: "default"}
	default:
		return fmt.Errorf("unexpected type: %s", ty)
	}
	return nil
}

func getType(schema *jsonschema.Schema) (string, *jsonschema.Schema, error) {
	t, err := getSimpleType(schema.Types)
	if err != nil {
		return "", nil, err
	}
	if t != "" {
		return t, schema, nil
	}
	if schema.Ref != nil {
		return getType(schema.Ref)
	}
	if len(schema.OneOf) > 0 {
		return "oneof", schema, nil
	}

	return "", nil, fmt.Errorf("could not determine type of %s", schema.Location)
}

func getSimpleType(types []string) (string, error) {
	if len(types) == 0 {
		return "", nil
	}
	if len(types) > 1 {
		return "", fmt.Errorf("too many types: %v", types)
	}
	return types[0], nil
}

// LoadTemplate loads a template from a TOML file.
func LoadTemplate(file string) (*Template, error) {
	var template struct {
		Root  string                    `toml:"root"`
		Types map[string]toml.Primitive `toml:"types"`
	}
	md, err := toml.DecodeFile(file, &template)
	if err != nil {
		return nil, err
	}

	types, err := decodeTypes(md, template.Types)
	if err != nil {
		return nil, err
	}

	return &Template{Types: types, Root: template.Root}, nil
}

func decodeTypes(
	md toml.MetaData,
	primTypes map[string]toml.Primitive,
) (map[string]TmplNode, error) {
	types := make(map[string]TmplNode)

	for name, rawType := range primTypes {
		tmpl, err := decodeType(md, rawType)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		types[name] = tmpl
	}
	return types, nil
}

func decodeType(md toml.MetaData, primType toml.Primitive) (TmplNode, error) {
	var primMap map[string]toml.Primitive
	if err := md.PrimitiveDecode(primType, &primMap); err != nil {
		return nil, err
	}

	var typename string
	if err := md.PrimitiveDecode(primMap["type"], &typename); err != nil {
		return nil, err
	}

	switch typename {
	case "string":
		return decodePrimitive[TmplString](md, primType)
	case "number":
		return decodePrimitive[TmplNumber](md, primType)
	case "array":
		return decodePrimitive[TmplArray](md, primType)
	case "oneof":
		return decodePrimitive[TmplOneOf](md, primType)
	case "object":
		return decodePrimitive[TmplObject](md, primType)
	default:
		return nil, fmt.Errorf("unknown type %v", typename)
	}
}

func decodePrimitive[T any](md toml.MetaData, primType toml.Primitive) (*T, error) {
	var template T
	if err := md.PrimitiveDecode(primType, &template); err != nil {
		return nil, err
	}
	return &template, nil
}
