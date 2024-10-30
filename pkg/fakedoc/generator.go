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
		children := make(map[string]any)
		for name, childType := range node.Children {
			child, err := gen.generateNode(childType, depth-1)
			if err != nil {
				return nil, err
			}
			children[name] = child
		}
		return children, nil
	case *TmplArray:
		if depth <= 0 {
			return []any{}, nil
		}
		length := gen.Rand.IntN(5)
		items := make([]any, length)
		for i := 0; i < length; i++ {
			item, err := gen.generateNode(node.Items, depth-1)
			if err != nil {
				return nil, err
			}
			items[i] = item
		}
		return items, nil
	case *TmplOneOf:
		typename := node.OneOf[gen.Rand.IntN(len(node.OneOf))]
		return gen.generateNode(typename, depth-1)
	case *TmplString:
		return gen.randomString(), nil
	case *TmplNumber:
		return gen.Rand.Int(), nil
	default:
		return nil, fmt.Errorf("unexpected template node type %T", nodeTmpl)
	}
}

func (gen *Generator) randomString() string {
	const chars = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var builder strings.Builder
	for i := 0; i < 10; i++ {
		builder.WriteByte(chars[gen.Rand.IntN(len(chars))])
	}
	return builder.String()
}
