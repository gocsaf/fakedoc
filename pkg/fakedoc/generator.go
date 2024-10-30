// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import "fmt"

// Generator is the type of CSAF document generators
type Generator struct {
	Template *Template
}

// NewGenerator creates a new Generator based on Template.
func NewGenerator(tmpl *Template) *Generator {
	return &Generator{
		Template: tmpl,
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
		item, err := gen.generateNode(node.Items, depth-1)
		if err != nil {
			return nil, err
		}
		return []any{item}, nil
	case *TmplOneOf:
		return gen.generateNode(node.OneOf[0], depth-1)
	case *TmplSimple:
		switch node.Type {
		case "string":
			return "some string", nil
		case "number":
			return 0, nil
		default:
			return nil, fmt.Errorf("unknown simple type '%s'", node.Type)
		}
	default:
		return nil, fmt.Errorf("unexpected template node type %T", nodeTmpl)
	}
}
