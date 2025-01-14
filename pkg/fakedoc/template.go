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
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const (
	uriRegexp = `(https?)://(example\.(com|org|net)|[a-zA-Z][a-zA-Z0-9]{10}\.example(/[a-zA-Z0-9.-]{1,10}){3})`

	// constants for the 'synthetic' template type for the product ID
	// generator
	productIDTypeName  = "fakedoc:product_id_generator"
	productIDNamespace = "product_id"
	groupIDTypeName    = "fakedoc:group_id_generator"
	groupIDNamespace   = "group_id"
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

// Merge adds the types of another template.
func (t *Template) Merge(other *Template) {
	for name, ty := range other.Types {
		t.Types[name] = ty
	}
}

// FromToml initializes a TmplNode from toml.MetaData and a
// toml.Primitive.
type FromToml interface {
	FromToml(md toml.MetaData, primType toml.Primitive) error
}

// TmplNode is the interface for template nodes.
type TmplNode interface {
	// AsMap returns a map describing the node for the TOML file
	AsMap() map[string]any

	// Instantiate creates an instance from this template node.
	Instantiate(gen *Generator, limits *LimitNode, depth int) (any, error)
}

// nodeFactories holds a map of node factories.
var nodeFactories = map[string]func() TmplNode{
	"string": func() TmplNode {
		return &TmplString{
			MinLength: -1,
			MaxLength: -1,
		}
	},
	"lorem": func() TmplNode {
		return &TmplLorem{
			MinLength: -1,
			MaxLength: -1,
			Unit:      LoremWords,
		}
	},
	"book": func() TmplNode {
		return &TmplBook{
			MinLength: -1,
			MaxLength: -1,
		}
	},
	"array": func() TmplNode {
		return &TmplArray{
			MinItems: -1,
			MaxItems: -1,
		}
	},
	"object": func() TmplNode {
		return &TmplObject{
			MinProperties: -1,
			MaxProperties: -1,
		}
	},
	"id":        func() TmplNode { return new(TmplID) },
	"ref":       func() TmplNode { return new(TmplRef) },
	"number":    func() TmplNode { return new(TmplNumber) },
	"date-time": func() TmplNode { return new(TmplDateTime) },
	"oneof":     func() TmplNode { return new(TmplOneOf) },
}

// Property describes how to generate one of an object's properties
type Property struct {
	Name     string `toml:"name"`
	Type     string `toml:"type"`
	Required bool   `toml:"required"`
}

// TmplObject describes a JSON object
type TmplObject struct {
	// Properties describes how to generate the object's properties.
	Properties []*Property `toml:"properties"`

	// MinProperties is the minimum number of properties that the
	// generated object must have. -1 means no limit.
	MinProperties int `toml:"minproperties"`

	// MaxProperties is the maximum number of properties that the
	// generated object must have. -1 means no limit.
	MaxProperties int `toml:"maxproperties"`
}

// AsMap implements TmplNode
func (t *TmplObject) AsMap() map[string]any {
	var props []map[string]any
	for _, p := range t.Properties {
		m := map[string]any{
			"name": p.Name,
			"type": p.Type,
		}
		if p.Required {
			m["required"] = p.Required
		}
		props = append(props, m)
	}

	m := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if t.MinProperties != -1 {
		m["minproperties"] = t.MinProperties
	}
	if t.MaxProperties != -1 {
		m["maxproperties"] = t.MaxProperties
	}
	return m
}

// FromToml implements FromToml
func (t *TmplObject) FromToml(md toml.MetaData, primType toml.Primitive) error {
	if err := md.PrimitiveDecode(primType, t); err != nil {
		return err
	}
	if len(t.Properties) < t.MinProperties {
		return fmt.Errorf(
			"%d properties < %d min properties",
			len(t.Properties), t.MinProperties,
		)
	}

	if t.MaxProperties >= 0 && t.MinProperties > t.MaxProperties {
		return fmt.Errorf(
			"minproperties %d > maxproperties %d",
			t.MinProperties, t.MaxProperties,
		)
	}

	return nil
}

// Instantiate implements TmplNode
func (t *TmplObject) Instantiate(gen *Generator, limits *LimitNode, depth int) (any, error) {
	return gen.generateObject(t, limits, depth)
}

// TmplArray describes a JSON array
type TmplArray struct {
	// Items is the type of the array items
	Items string `toml:"items"`

	// MinItems is the minimum length of the generated array
	MinItems int `toml:"minitems"`
	// MaxLength is the maximum length of the generated array
	MaxItems int `toml:"maxitems"`

	UniqueItems bool `toml:"uniqueitems"`
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
	if t.UniqueItems {
		m["uniqueitems"] = t.UniqueItems
	}
	return m
}

// Instantiate implements TmplNode
func (t *TmplArray) Instantiate(gen *Generator, limits *LimitNode, depth int) (any, error) {
	return gen.randomArray(t, limits, depth)
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

// Instantiate implements TmplNode
func (t *TmplOneOf) Instantiate(gen *Generator, limits *LimitNode, depth int) (any, error) {
	return gen.randomOneOf(t.OneOf, limits, depth)
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

// Instantiate implements TmplNode
func (t *TmplString) Instantiate(gen *Generator, _ *LimitNode, _ int) (any, error) {
	if len(t.Enum) > 0 {
		return choose(gen.Rand, t.Enum), nil
	}
	if t.Pattern != nil {
		return t.Pattern.Sample(gen.Rand), nil
	}
	return gen.randomString(t.MinLength, t.MaxLength), nil
}

// TmplLorem describes how to generate strings
type TmplLorem struct {
	// MinLength is the minimum length of the generated strings
	MinLength int `toml:"minlength"`
	// MaxLength is the maximum length of the generated strings
	MaxLength int `toml:"maxlength"`
	// Unit for max/min length. Can be "words", "sentences" or
	// "paragraphs". Default is "words"
	Unit LoremUnit
}

// LoremUnit represents the granularity of the lorem ipsum generator
type LoremUnit string

// TmplBook describes the text file for string generation
type TmplBook struct {
	// MinLength is the minimum length of the generated strings
	MinLength int `toml:"minlength"`
	// MaxLength is the maximum length of the generated strings
	MaxLength int `toml:"maxlength"`
	// Path is the location of the text file
	Path string `toml:"path"`
}

const (
	// LoremWords indicates that a bunch of words should be generated
	LoremWords LoremUnit = "words"
	// LoremSentences indicates that full sentences should be generated
	LoremSentences LoremUnit = "sentences"
	// LoremParagraphs indicates that complete paragraphs should be generated
	LoremParagraphs LoremUnit = "paragraphs"
)

// AsMap implements TmplNode
func (t *TmplLorem) AsMap() map[string]any {
	m := map[string]any{
		"type": "lorem",
	}
	if t.MinLength != -1 {
		m["minlength"] = t.MinLength
	}
	if t.MaxLength != -1 {
		m["maxlength"] = t.MaxLength
	}
	if t.Unit != LoremWords {
		m["unit"] = t.Unit
	}
	return m
}

// Instantiate implements TmplNode
func (t *TmplLorem) Instantiate(gen *Generator, _ *LimitNode, _ int) (any, error) {
	return gen.loremIpsum(t.MinLength, t.MaxLength, t.Unit), nil
}

// AsMap implements TmplNode
func (t *TmplBook) AsMap() map[string]any {
	m := map[string]any{
		"type": "book",
	}
	if t.MinLength != -1 {
		m["minlength"] = t.MinLength
	}
	if t.MaxLength != -1 {
		m["maxlength"] = t.MaxLength
	}
	if t.Path != "" {
		m["path"] = t.Path
	}
	return m
}

// Instantiate implements TmplNode
func (t *TmplBook) Instantiate(gen *Generator, _ *LimitNode, _ int) (any, error) {
	return gen.book(t.MinLength, t.MaxLength, t.Path)
}

// TmplID describes how to generate IDs that may be referenced from
// elsewhere in the document by TmplRef types using the same namespace.
type TmplID struct {
	// Namespace is the namespace for the IDs
	Namespace string `toml:"namespace"`
}

// AsMap implements TmplNode
func (t *TmplID) AsMap() map[string]any {
	return map[string]any{
		"type":      "id",
		"namespace": t.Namespace,
	}
}

// Instantiate implements TmplNode
func (t *TmplID) Instantiate(gen *Generator, _ *LimitNode, _ int) (any, error) {
	return gen.generateID(t.Namespace), nil
}

// TmplRef generate strings that are chosen from the IDs generated for
// the TmplID with the same namespace
type TmplRef struct {
	// Namespace is the namespace for the IDs
	Namespace string `toml:"namespace"`
}

// AsMap implements TmplNode
func (t *TmplRef) AsMap() map[string]any {
	return map[string]any{
		"type":      "ref",
		"namespace": t.Namespace,
	}
}

// Instantiate implements TmplNode
func (t *TmplRef) Instantiate(gen *Generator, _ *LimitNode, _ int) (any, error) {
	return gen.generateReference(t.Namespace)
}

// TmplNumber describes how to generate numbers
type TmplNumber struct {
	// Minimum is the minum value of the generated numbers
	Minimum *float32 `toml:"minimum"`

	// Maximum is the maximum value of the generated numbers
	Maximum *float32 `toml:"maximum"`
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

// Instantiate implements TmplNode
func (t *TmplNumber) Instantiate(gen *Generator, _ *LimitNode, _ int) (any, error) {
	return gen.randomNumber(t.Minimum, t.Maximum), nil
}

// TmplDateTime describes how to generate date/time values
type TmplDateTime struct {
	// Minimum is the minum value of the generated date/time values
	Minimum *time.Time `toml:"minimum"`

	// Maximum is the maximum value of the generated  date/time values
	Maximum *time.Time `toml:"maximum"`
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

// Instantiate implements TmplNode
func (t *TmplDateTime) Instantiate(gen *Generator, _ *LimitNode, _ int) (any, error) {
	return gen.randomDateTime(t.Minimum, t.Maximum), nil
}

// FromCSAFSchema creates a new template from the built-in CSAF JSON
// schema
func FromCSAFSchema() (*Template, error) {
	schema, err := CompileSchema()
	if err != nil {
		return nil, err
	}

	return FromSchema(schema)
}

// FromSchema creates a default template from a JSON schema.
func FromSchema(schema *jsonschema.Schema) (*Template, error) {
	template := &Template{
		Types: make(map[string]TmplNode),
		Root:  "",
	}
	root, err := template.fromSchema(schema)
	if err != nil {
		return nil, err
	}
	template.Root = root

	if err := template.applyCSAFSpecials(); err != nil {
		return nil, err
	}

	return template, nil
}

func (t *Template) fromSchema(origschema *jsonschema.Schema) (string, error) {
	ty, schema, err := getType(origschema)
	if err != nil {
		return "", err
	}

	name := ShortLocation(schema)

	// Check for recursion. If name is already in t.Types, we don't have
	// to do anything. If the associated value is nil, we're currently
	// building the node, otherwise the node has already been
	// constructed.
	if _, ok := t.Types[name]; ok {
		return name, nil
	}
	t.Types[name] = nil

	switch ty {
	case "object":
		required := make(map[string]bool, len(schema.Required))
		for _, name := range schema.Required {
			required[name] = true
		}

		properties := []*Property{}
		for propName, prop := range schema.Properties {
			propType, err := t.fromSchema(prop)
			if err != nil {
				return "", err
			}
			properties = append(properties, &Property{
				Name:     propName,
				Type:     propType,
				Required: required[propName],
			})
		}
		// Sort properties by name to make the output deterministic
		slices.SortFunc(properties, func(p1, p2 *Property) int {
			return cmp.Compare(p1.Name, p2.Name)
		})

		t.Types[name] = &TmplObject{
			Properties:    properties,
			MinProperties: schema.MinProperties,
			MaxProperties: schema.MaxProperties,
		}
	case "array":
		itemsType, err := t.fromSchema(schema.Items2020)
		if err != nil {
			return "", err
		}
		t.Types[name] = &TmplArray{
			Items:       itemsType,
			MinItems:    schema.MinItems,
			MaxItems:    schema.MaxItems,
			UniqueItems: schema.UniqueItems,
		}
	case "oneof":
		oneof := []string{}
		for _, alternative := range schema.OneOf {
			altType, err := t.fromSchema(alternative)
			if err != nil {
				return "", err
			}
			oneof = append(oneof, altType)
		}
		t.Types[name] = &TmplOneOf{OneOf: oneof}
	case "string":
		switch schema.Format {
		case "date-time":
			mindate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			maxdate := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			t.Types[name] = &TmplDateTime{Minimum: &mindate, Maximum: &maxdate}
		default:
			enum := []string{}
			for _, v := range schema.Enum {
				enum = append(enum, v.(string))
			}
			regexp := ""
			if schema.Pattern != nil {
				regexp = schema.Pattern.String()
			}
			if schema.Format == "uri" && regexp == "" {
				regexp = uriRegexp
			}

			var pattern *Pattern
			if regexp != "" {
				pattern, err = CompileRegexp(regexp)
				if err != nil {
					return "", err
				}
			}

			t.Types[name] = &TmplString{
				MinLength: schema.MinLength,
				MaxLength: schema.MaxLength,
				Enum:      enum,
				Pattern:   pattern,
			}
		}
	case "number":
		var minimum, maximum *float32
		if schema.Minimum != nil {
			m, _ := schema.Minimum.Float32()
			minimum = &m
		}
		if schema.Maximum != nil {
			m, _ := schema.Maximum.Float32()
			maximum = &m
		}
		t.Types[name] = &TmplNumber{
			Minimum: minimum,
			Maximum: maximum,
		}
	default:
		return "", fmt.Errorf("unexpected type: %s", ty)
	}
	return name, nil
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

func (t *Template) applyCSAFSpecials() error {
	t.Types[productIDTypeName] = &TmplID{
		Namespace: productIDNamespace,
	}
	t.Types[groupIDTypeName] = &TmplID{
		Namespace: groupIDNamespace,
	}

	var errs []error
	collectErr := func(err error) {
		errs = append(errs, err)
	}

	collectErr(t.modifyProperty(
		"csaf:#/$defs/full_product_name_t",
		"product_id",
		func(p *Property) error {
			p.Type = productIDTypeName
			return nil
		},
	))

	collectErr(t.modifyProperty(
		"csaf:#/properties/product_tree/properties/product_groups/items",
		"group_id",
		func(p *Property) error {
			p.Type = groupIDTypeName
			return nil
		},
	))

	collectErr(t.overwriteType(
		"csaf:#/$defs/product_id_t",
		&TmplRef{
			Namespace: productIDNamespace,
		},
	))
	collectErr(t.overwriteType(
		"csaf:#/$defs/product_group_id_t",
		&TmplRef{
			Namespace: groupIDNamespace,
		},
	))

	return errors.Join(errs...)
}

func (t *Template) overwriteType(typename string, tmpl TmplNode) error {
	_, ok := t.Types[typename]
	if !ok {
		return fmt.Errorf("type %s does not exist", typename)
	}
	t.Types[typename] = tmpl
	return nil
}

func (t *Template) modifyProperty(
	typename, propname string,
	modify func(*Property) error,
) error {
	tmpl, ok := t.Types[typename]
	if !ok {
		return fmt.Errorf("type %s does not exist", typename)
	}
	obj, ok := tmpl.(*TmplObject)
	if !ok {
		return fmt.Errorf("type %s is not a TmplObject", typename)
	}
	for _, p := range obj.Properties {
		if p.Name == propname {
			return modify(p)
		}
	}
	return fmt.Errorf("type %s has no property %s", typename, propname)
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

	factory := nodeFactories[typename]
	if factory == nil {
		return nil, fmt.Errorf("unknown type %v", typename)
	}
	node := factory()
	var err error
	if ft, ok := node.(FromToml); ok {
		err = ft.FromToml(md, primType)
	} else {
		err = md.PrimitiveDecode(primType, node)
	}
	if err != nil {
		return nil, err
	}
	return node, nil
}
