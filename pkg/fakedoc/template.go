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

	// FromToml initializes a TmplNode from toml.MetaData and a
	// toml.Primitive.
	FromToml(md toml.MetaData, primType toml.Primitive) error
}

// TmplObject describes a JSON object
type TmplObject struct {
	// Properties contains the names of the properties and their
	// corresponding type
	Properties map[string]string `toml:"properties"`

	Probabilities map[string]float32 `toml:"probabilities"`
}

// AsMap implements TmplNode
func (t *TmplObject) AsMap() map[string]any {
	return map[string]any{
		"type":          "object",
		"properties":    t.Properties,
		"probabilities": t.Probabilities,
	}
}

// FromToml implemts TmplNode
func (t *TmplObject) FromToml(md toml.MetaData, primType toml.Primitive) error {
	if err := md.PrimitiveDecode(primType, t); err != nil {
		return err
	}
	return nil
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
func (t *TmplArray) AsMap() map[string]any {
	return map[string]any{
		"type":     "array",
		"items":    t.Items,
		"minitems": t.MinItems,
		"maxitems": t.MaxItems,
	}
}

// FromToml implemts TmplNode
func (t *TmplArray) FromToml(md toml.MetaData, primType toml.Primitive) error {
	if err := md.PrimitiveDecode(primType, t); err != nil {
		return err
	}
	return nil
}

// TmplOneOf describes the choice between multiple types
type TmplOneOf struct {
	// OneOf contains the types between which to choose
	OneOf []string `toml:"oneof"`
}

// AsMap implements TmplNode
func (t *TmplOneOf) AsMap() map[string]any {
	return map[string]any{
		"type":  "oneof",
		"oneof": t.OneOf,
	}
}

// FromToml implemts TmplNode
func (t *TmplOneOf) FromToml(md toml.MetaData, primType toml.Primitive) error {
	if err := md.PrimitiveDecode(primType, t); err != nil {
		return err
	}
	return nil
}

// TmplString describes how to generate strings
type TmplString struct {
	// MinLength is the minimum length of the generated strings
	MinLength int `toml:"minlength"`
	// MaxLength is the maximum length of the generated strings
	MaxLength int `toml:"maxlength"`

	// Enum contains the values to choose from.
	Enum []string `toml:"enum"`

	// Pattern is a regular expression the string should match
	Pattern string `toml:"pattern"`

	// compiled is a compiled version of Pattern, usable for generating
	// strings.
	compiled *Pattern

	// Which generator to use. For now, this should be "default"
	Generator string `toml:"generator"`
}

// AsMap implements TmplNode
func (t *TmplString) AsMap() map[string]any {
	return map[string]any{
		"type":      "string",
		"minlength": t.MinLength,
		"maxlength": t.MaxLength,
		"enum":      t.Enum,
		"pattern":   t.Pattern,
		"generator": t.Generator,
	}
}

// FromToml implemts TmplNode
func (t *TmplString) FromToml(md toml.MetaData, primType toml.Primitive) error {
	if err := md.PrimitiveDecode(primType, t); err != nil {
		return err
	}
	return nil
}

// TmplNumber describes how to generate numbers
type TmplNumber struct {
	// Minimum is the minum value of the generated numbers
	Minimum *float32

	// Maximum is the maximum value of the generated numbers
	Maximum *float32

	// Which generator to use. For now, this should be "default"
	Generator string `toml:"generator"`
}

// AsMap implements TmplNode
func (t *TmplNumber) AsMap() map[string]any {
	return map[string]any{
		"type":      "number",
		"minimum":   t.Minimum,
		"maximum":   t.Maximum,
		"generator": t.Generator,
	}
}

// FromToml implemts TmplNode
func (t *TmplNumber) FromToml(md toml.MetaData, primType toml.Primitive) error {
	if err := md.PrimitiveDecode(primType, t); err != nil {
		return err
	}
	return nil
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
		pattern := ""
		if tschema.Pattern != nil {
			pattern = tschema.Pattern.String()
		}
		t.Types[name] = &TmplString{
			MinLength: tschema.MinLength,
			MaxLength: tschema.MaxLength,
			Enum:      enum,
			Pattern:   pattern,
			Generator: "default",
		}
	case "number":
		var minimum, maximum *float32
		if tschema.Minimum != nil {
			m, _ := tschema.Minimum.Float32()
			minimum = &m
		}
		if tschema.Maximum != nil {
			m, _ := tschema.Maximum.Float32()
			maximum = &m
		}
		t.Types[name] = &TmplNumber{
			Minimum:   minimum,
			Maximum:   maximum,
			Generator: "default",
		}
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

	var node TmplNode
	switch typename {
	case "string":
		node = new(TmplString)
	case "number":
		node = new(TmplNumber)
	case "array":
		node = new(TmplArray)
	case "oneof":
		node = new(TmplOneOf)
	case "object":
		node = new(TmplObject)
	default:
		return nil, fmt.Errorf("unknown type %v", typename)
	}
	if err := node.FromToml(md, primType); err != nil {
		return nil, err
	}

	return node, nil
}
