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
	"math/rand/v2"
	"strings"
)

// Generator is the type of CSAF document generators
type Generator struct {
	Template *Template
	Rand     *rand.Rand
}

// NewGenerator creates a new Generator based on Template.
func NewGenerator(tmpl *Template) *Generator {
	return &Generator{
		Template: tmpl,
		Rand:     rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	}
}

// Generate generates a document
func (gen *Generator) Generate() (any, error) {
	return gen.generateNode(gen.Template.Root, 25)
}

func (gen *Generator) generateNode(typename string, depth int) (any, error) {
	nodeTmpl, ok := gen.Template.Types[typename]
	if !ok {
		return nil, fmt.Errorf("unknown type '%s'", typename)
	}
	switch node := nodeTmpl.(type) {
	case *TmplObject:
		return gen.generateObject(node, depth)
	case *TmplArray:
		if depth <= 0 {
			return []any{}, nil
		}
		return gen.randomArray(node, depth)
	case *TmplOneOf:
		typename := choose(gen.Rand, node.OneOf)
		return gen.generateNode(typename, depth-1)
	case *TmplString:
		if len(node.Enum) > 0 {
			return choose(gen.Rand, node.Enum), nil
		}
		return gen.randomString(node.MinLength, node.MaxLength), nil
	case *TmplNumber:
		return gen.Rand.Int(), nil
	default:
		return nil, fmt.Errorf("unexpected template node type %T", nodeTmpl)
	}
}

func (gen *Generator) randomString(minlength, maxlength int) string {
	const chars = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if minlength < 0 {
		minlength = 0
	}
	if maxlength < 0 {
		// FIXME: make bound on maximum length configurable
		maxlength = minlength + 10
	}
	length := minlength + gen.Rand.IntN(maxlength-minlength+1)
	var builder strings.Builder
	for i := 0; i < length; i++ {
		builder.WriteByte(choose(gen.Rand, []byte(chars)))
	}
	return builder.String()
}

func (gen *Generator) randomArray(tmpl *TmplArray, depth int) (any, error) {
	minitems := tmpl.MinItems
	maxitems := tmpl.MaxItems

	if minitems < 0 {
		minitems = 0
	}
	if maxitems < 0 {
		// FIXME: make bound on maximum length configurable
		maxitems = minitems + 2
	}

	length := minitems + gen.Rand.IntN(maxitems-minitems+1)
	items := make([]any, length)
	for i := 0; i < length; i++ {
		item, err := gen.generateNode(tmpl.Items, depth-1)
		if err != nil {
			return nil, err
		}
		items[i] = item
	}
	return items, nil
}

func (gen *Generator) generateObject(node *TmplObject, depth int) (any, error) {
	properties := make(map[string]any)
	for name, propType := range node.Properties {
		probabiliy, ok := node.Probabilities[name]
		if !ok || gen.Rand.Float32() > probabiliy {
			continue
		}
		prop, err := gen.generateNode(propType, depth-1)
		if err != nil {
			return nil, err
		}
		properties[name] = prop
	}
	return properties, nil
}
