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
	// Children contains the names of the properties and their
	// corresponding type
	Children map[string]string
}

// AsMap implements TmplNode
func (to *TmplObject) AsMap() map[string]any {
	return map[string]any{
		"type":     "object",
		"children": to.Children,
	}
}

// TmplArray describes a JSON array
type TmplArray struct {
	// Items is the type of the array items
	Items string
}

// AsMap implements TmplNode
func (ta *TmplArray) AsMap() map[string]any {
	return map[string]any{
		"type":  "array",
		"items": ta.Items,
	}
}

// TmplSimple describes a simple type like strings and numbers
type TmplSimple struct {
	// Type, e.g. "string", "number"
	Type string

	// Which generator to use. For now, this shoudl be "default"
	Generator string
}

// AsMap implements TmplNode
func (ts *TmplSimple) AsMap() map[string]any {
	return map[string]any{
		"type":      ts.Type,
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
		children := make(map[string]string)
		for childName, child := range tschema.Properties {
			if err := t.fromSchema(child); err != nil {
				return err
			}
			children[childName] = ShortLocation(child)
		}
		t.Types[name] = &TmplObject{Children: children}
	case "array":
		if err := t.fromSchema(tschema.Items2020); err != nil {
			return err
		}
		t.Types[name] = &TmplArray{Items: ShortLocation(tschema.Items2020)}
	case "string":
		t.Types[name] = &TmplSimple{Type: "string", Generator: "default"}
	case "number":
		t.Types[name] = &TmplSimple{Type: "number", Generator: "default"}
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
		// FIXME: handle OneOf properly
		return getType(schema.OneOf[0])
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
	var tree map[string]any
	_, err := toml.DecodeFile(file, &tree)
	if err != nil {
		return nil, err
	}

	root, err := get[string](tree, "root")
	if err != nil {
		return nil, err
	}

	rawTypes, err := get[map[string]any](tree, "types")
	if err != nil {
		return nil, err
	}

	types, err := fromRawNodes(rawTypes)
	if err != nil {
		return nil, err
	}

	return &Template{Types: types, Root: root}, nil
}

func fromRawNodes(rawTypes map[string]any) (map[string]TmplNode, error) {
	types := make(map[string]TmplNode)

	for name, rawType := range rawTypes {
		tmpl, err := fromRawType(rawType.(map[string]any))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		types[name] = tmpl
	}
	return types, nil
}

func fromRawType(rawType map[string]any) (TmplNode, error) {
	gentype, err := get[string](rawType, "type")
	if err != nil {
		return nil, err
	}
	switch gentype {
	case "string", "number":
		generator, err := get[string](rawType, "generator")
		if err != nil {
			return nil, err
		}
		return &TmplSimple{Generator: generator, Type: gentype}, nil
	case "array":
		items, err := get[string](rawType, "items")
		if err != nil {
			return nil, err
		}
		return &TmplArray{Items: items}, nil
	case "object":
		rawChildren, err := get[map[string]any](rawType, "children")
		if err != nil {
			return nil, err
		}
		children := make(map[string]string)
		for name, rawType := range rawChildren {
			typename, ok := rawType.(string)
			if !ok {
				return nil, fmt.Errorf("expected string, got %T", rawType)
			}
			children[name] = typename
		}
		return &TmplObject{Children: children}, nil
	default:
		return nil, fmt.Errorf("unknown type %v", gentype)
	}
}

func get[T any](m map[string]any, key string) (T, error) {
	var value T
	v, ok := m[key]
	if !ok {
		return value, fmt.Errorf("missing '%s'", key)
	}
	value, ok = v.(T)
	if !ok {
		return value, fmt.Errorf("expected type %T, got %T", value, v)
	}
	return value, nil
}
