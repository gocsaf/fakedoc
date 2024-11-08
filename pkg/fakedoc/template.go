// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"time"

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

// Property describes how to generate one of an object's properties
type Property struct {
	Name        string  `toml:"name"`
	Type        string  `toml:"type"`
	Probability float32 `toml:"probability"`
}

// TmplObject describes a JSON object
type TmplObject struct {
	// Properties describes how to generate the object's properties.
	Properties []*Property `toml:"properties"`
}

// AsMap implements TmplNode
func (t *TmplObject) AsMap() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": t.Properties,
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
	m := map[string]any{
		"type":  "array",
		"items": t.Items,
	}
	if t.MinItems != -1 {
		m["minitems"] = t.MinItems
	}
	if t.MaxItems != -1 {
		m["maxitems"] = t.MaxItems
	}
	return m
}

// FromToml implemts TmplNode
func (t *TmplArray) FromToml(md toml.MetaData, primType toml.Primitive) error {
	t.MinItems = -1
	t.MaxItems = -1
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

	// Pattern represents a regular expression the string should match
	Pattern *Pattern `toml:"pattern"`
}

// AsMap implements TmplNode
func (t *TmplString) AsMap() map[string]any {
	m := map[string]any{
		"type": "string",
	}
	if t.MinLength != -1 {
		m["minlength"] = t.MinLength
	}
	if t.MaxLength != -1 {
		m["maxlength"] = t.MaxLength
	}
	if len(t.Enum) > 0 {
		m["enum"] = t.Enum
	}
	if t.Pattern != nil {
		m["pattern"] = t.Pattern.Pattern
	}
	return m
}

// FromToml implemts TmplNode
func (t *TmplString) FromToml(md toml.MetaData, primType toml.Primitive) error {
	t.MinLength = -1
	t.MaxLength = -1
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
}

// AsMap implements TmplNode
func (t *TmplNumber) AsMap() map[string]any {
	m := map[string]any{
		"type": "number",
	}
	if t.Minimum != nil {
		m["minimum"] = *t.Minimum
	}
	if t.Maximum != nil {
		m["maximum"] = *t.Maximum
	}
	return m
}

// FromToml implemts TmplNode
func (t *TmplNumber) FromToml(md toml.MetaData, primType toml.Primitive) error {
	if err := md.PrimitiveDecode(primType, t); err != nil {
		return err
	}
	return nil
}

// TmplDateTime describes how to generate date/time values
type TmplDateTime struct {
	// Minimum is the minum value of the generated date/time values
	Minimum *time.Time

	// Maximum is the maximum value of the generated  date/time values
	Maximum *time.Time
}

// AsMap implements TmplNode
func (t *TmplDateTime) AsMap() map[string]any {
	m := map[string]any{
		"type": "date-time",
	}
	if t.Minimum != nil {
		m["minimum"] = *t.Minimum
	}
	if t.Maximum != nil {
		m["maximum"] = *t.Maximum
	}
	return m
}

// FromToml implemts TmplNode
func (t *TmplDateTime) FromToml(md toml.MetaData, primType toml.Primitive) error {
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
		// Preset probabilities for the properties. Required properties
		// have probability 1
		probabilities := map[string]float32{}
		for _, name := range tschema.Required {
			probabilities[name] = 1.0
		}

		properties := []*Property{}
		for propName, prop := range tschema.Properties {
			if err := t.fromSchema(prop); err != nil {
				return err
			}
			probability, ok := probabilities[propName]
			if !ok {
				// The property is not required, so use some value < 1.
				probability = 0.5
			}
			properties = append(properties, &Property{
				Name:        propName,
				Type:        ShortLocation(prop),
				Probability: probability,
			})
		}

		// Sort properties by name to make the output deterministic
		slices.SortFunc(properties, func(p1, p2 *Property) int {
			return cmp.Compare(p1.Name, p2.Name)
		})

		t.Types[name] = &TmplObject{
			Properties: properties,
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
		switch tschema.Format {
		case "date-time":
			mindate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			maxdate := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			t.Types[name] = &TmplDateTime{Minimum: &mindate, Maximum: &maxdate}
		default:
			enum := []string{}
			for _, v := range tschema.Enum {
				enum = append(enum, v.(string))
			}
			var pattern *Pattern
			if tschema.Pattern != nil {
				pattern, err = CompileRegexp(tschema.Pattern.String())
				if err != nil {
					return nil
				}
			}
			t.Types[name] = &TmplString{
				MinLength: tschema.MinLength,
				MaxLength: tschema.MaxLength,
				Enum:      enum,
				Pattern:   pattern,
			}
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
			Minimum: minimum,
			Maximum: maximum,
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
	case "date-time":
		node = new(TmplDateTime)
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
