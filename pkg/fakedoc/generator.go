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
	"math"
	"math/rand/v2"
	"strings"
	"time"
)

// Generator is the type of CSAF document generators
type Generator struct {
	Template *Template
	Rand     *rand.Rand
}

// NewGenerator creates a new Generator based on a Template and an
// optional random number generator. If the random number generator is
// nil, a random number generator with a random seed will be used.
func NewGenerator(tmpl *Template, rng *rand.Rand) *Generator {
	if rng == nil {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}
	return &Generator{
		Template: tmpl,
		Rand:     rng,
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
		if node.Pattern != nil {
			return node.Pattern.Sample(gen.Rand), nil
		}
		return gen.randomString(node.MinLength, node.MaxLength), nil
	case *TmplNumber:
		return gen.randomNumber(node.Minimum, node.Maximum), nil
	case *TmplDateTime:
		return gen.randomDateTime(node.Minimum, node.Maximum), nil
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
	for range length {
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
	for i := range length {
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
	for _, prop := range node.Properties {
		if gen.Rand.Float32() > prop.Probability {
			continue
		}
		value, err := gen.generateNode(prop.Type, depth-1)
		if err != nil {
			return nil, err
		}
		properties[prop.Name] = value
	}
	return properties, nil
}

func (gen *Generator) randomNumber(minimum, maximum *float32) float32 {
	low := float64(-math.MaxFloat32)
	high := float64(math.MaxFloat32)
	if minimum != nil {
		low = float64(*minimum)
	}
	if maximum != nil {
		high = float64(*maximum)
	}

	return float32(low + gen.Rand.Float64()*(high-low))
}

func (gen *Generator) randomDateTime(mindate, maxdate *time.Time) time.Time {
	if mindate == nil {
		if maxdate == nil {
			now := time.Now()
			maxdate = &now
		}
		d := maxdate.AddDate(-1, 0, 0)
		mindate = &d
	}
	if maxdate == nil {
		d := mindate.AddDate(1, 0, 0)
		maxdate = &d
	}
	duration := maxdate.Sub(*mindate)

	return mindate.Add(time.Duration(gen.Rand.Float64() * float64(duration)))
}
