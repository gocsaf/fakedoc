// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-loremipsum/loremipsum"
)

// ErrBranchAbandoned is the base errors that indicate that the
// generator should abandon a recursive descent and try again with a
// different branch.
//
// This error is mostly used internally in the generator and is unlikely
// to be returned from Generate method.
var ErrBranchAbandoned = errors.New("branch abandoned")

// ErrDepthExceeded is returned as error by the generator if exceeding
// the maximum depth of the generated document could not be avoided.
// It is based on ErrBranchAbandoned
var ErrDepthExceeded = fmt.Errorf("%w: maximum depth exceeded", ErrBranchAbandoned)

// ErrNoValidValue is returned as error by the generator if no value
// that conforms to the constraints given in the template could be
// generated. This can happen for arrays where UniqueItems is true, for
// instance, if the minimum number of items is large compared to number
// of different valid items.
var ErrNoValidValue = errors.New("could not generate valid value")

// ErrInvalidString is returned as error by the generator if the input
// text is not valid UTF-8. This can happen if the input is a binary
// file not a text document.
var ErrInvalidString = errors.New("not valid utf-8")

// Generator is the type of CSAF document generators
type Generator struct {
	Template  *Template
	Rand      *rand.Rand
	FileCache map[string]string
}

// NewGenerator creates a new Generator based on a Template and an
// optional random number generator. If the random number generator is
// nil, a random number generator with a random seed will be used.
func NewGenerator(tmpl *Template, rng *rand.Rand) *Generator {
	if rng == nil {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}
	return &Generator{
		Template:  tmpl,
		Rand:      rng,
		FileCache: make(map[string]string),
	}
}

// Generate generates a document
func (gen *Generator) Generate() (any, error) {
	return gen.generateNode(gen.Template.Root, 25)
}

func (gen *Generator) generateNode(typename string, depth int) (any, error) {
	if depth <= 0 {
		return nil, ErrDepthExceeded
	}

	nodeTmpl, ok := gen.Template.Types[typename]
	if !ok {
		return nil, fmt.Errorf("unknown type '%s'", typename)
	}
	switch node := nodeTmpl.(type) {
	case *TmplObject:
		return gen.generateObject(node, depth)
	case *TmplArray:
		return gen.randomArray(node, depth)
	case *TmplOneOf:
		return gen.randomOneOf(node.OneOf, depth)
	case *TmplString:
		if len(node.Enum) > 0 {
			return choose(gen.Rand, node.Enum), nil
		}
		if node.Pattern != nil {
			return node.Pattern.Sample(gen.Rand), nil
		}
		return gen.randomString(node.MinLength, node.MaxLength), nil
	case *TmplLorem:
		return gen.loremIpsum(node.MinLength, node.MaxLength, node.Unit), nil
	case *TmplBook:
		return gen.book(node.MinLength, node.MaxLength, node.Path)
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
	items := make([]any, 0, length)
	notInItems := func(v any) bool {
		if !tmpl.UniqueItems {
			return true
		}
		return !slices.ContainsFunc(items, func(item any) bool {
			return reflect.DeepEqual(item, v)
		})
	}
	for range length {
		item, err := gen.generateItemUntil(tmpl.Items, 10, depth-1, notInItems)
		switch {
		case errors.Is(err, ErrNoValidValue):
			continue
		case err != nil:
			return nil, err
		}
		items = append(items, item)
	}

	if len(items) < minitems {
		// Should only happen if we could not generate enough unique
		// elements for the array.
		return nil, ErrNoValidValue
	}

	return items, nil
}

// generateItemUntil repeatedly tries to generate an item of type
// typename until an item has been generated for which cond returns
// true. If no such item could be generated in maxAttempts attempts,
// ErrNoValidValue is returned as error. There may be other errors if
// generating an item fails for other reasons.
func (gen *Generator) generateItemUntil(
	typename string,
	maxAttempts int,
	depth int,
	cond func(any) bool,
) (any, error) {
	var (
		item    any
		err     error
		success bool
	)

generateItem:
	for range maxAttempts {
		item, err = gen.generateNode(typename, depth-1)
		switch {
		case err != nil:
			return nil, err
		case !cond(item):
			continue
		default:
			success = true
			break generateItem
		}
	}
	if !success {
		return nil, ErrNoValidValue
	}
	return item, nil
}

func (gen *Generator) randomOneOf(oneof []string, depth int) (any, error) {
	shuffled := shuffle(gen.Rand, oneof)
	var abandoned error
	for _, typename := range shuffled {
		value, err := gen.generateNode(typename, depth-1)
		if errors.Is(err, ErrBranchAbandoned) {
			abandoned = err
			continue
		}
		return value, err
	}

	if abandoned != nil {
		return nil, abandoned
	}
	return nil, fmt.Errorf("could not generate any of %v", oneof)
}

func (gen *Generator) generateObject(node *TmplObject, depth int) (any, error) {
	properties := make(map[string]any)
	optional := make([]*Property, 0, len(node.Properties))
	for _, prop := range node.Properties {
		switch {
		case prop.Required:
			value, err := gen.generateNode(prop.Type, depth-1)
			if err != nil {
				return nil, err
			}
			properties[prop.Name] = value
		default:
			optional = append(optional, prop)
		}
	}

	// Choose a value for extraProps, the number of optional properties
	// to add based on how many we need at least, node.MinProperties,
	// and how many we may have at most, node.MaxProperties. Both of
	// those may be -1, which means that there are no explicit limits.
	// For the lower bound on the number of properties we can just use
	// the maximum of the number of required properties and
	// MinProperties, minProps. For the upper bound, we choose
	// MaxProperties if it is not negative and the total number of known
	// properties, maxProps. The extra props then, are at least the
	// number of properties still missing in order to reach minProps and
	// at most maxProps. If maxProps > minProps we choose a random
	// number in that range.
	minProps := max(node.MinProperties, len(properties))
	maxProps := node.MaxProperties
	if maxProps < 0 {
		maxProps = len(node.Properties)
	}
	extraProps := minProps - len(properties)
	if maxProps > minProps {
		extraProps += gen.Rand.IntN(maxProps - minProps + 1)
	}

	// generate more properties until we've either generated extraProps
	// additional properties or we run out of optional properties to
	// try. Generating a property may fail because the maximum depth
	// would be exceeded in which case we just try again with a
	// different property.
	var branchAbandoned error
	for extraProps > 0 && len(optional) > 0 {
		i := gen.Rand.IntN(len(optional))
		prop := optional[i]
		optional = slices.Delete(optional, i, i+1)
		value, err := gen.generateNode(prop.Type, depth-1)
		switch {
		case errors.Is(err, ErrBranchAbandoned):
			branchAbandoned = err
			continue
		case err != nil:
			return nil, err
		}
		properties[prop.Name] = value
		extraProps--
	}

	// If we failed to generate at least minProps properties, we've
	// failed to generate a valid object, so we return an error. If the
	// failure is due to exceeding the maximum depth we report that to
	// the caller so that it can try something else.
	if len(properties) < minProps {
		if branchAbandoned != nil {
			return nil, branchAbandoned
		}
		return nil, fmt.Errorf("could not generate at least %d properties", minProps)
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

func (gen *Generator) loremIpsum(minlength, maxlength int, unit LoremUnit) string {
	if minlength < 0 {
		minlength = 0
	}
	if maxlength < 0 {
		// FIXME: make bound on maximum length configurable
		maxlength = minlength + 10
	}

	length := minlength + gen.Rand.IntN(maxlength-minlength)

	lorem := loremipsum.NewWithSeed(gen.Rand.Int64())
	switch unit {
	case LoremSentences:
		return lorem.Sentences(length)
	case LoremParagraphs:
		return lorem.Paragraphs(length)
	default:
		return lorem.Words(length)
	}
}

func (gen *Generator) book(minlength, maxlength int, path string) (string, error) {
	if minlength < 0 {
		minlength = 0
	}
	if maxlength < 0 {
		// FIXME: make bound on maximum length configurable
		maxlength = minlength + 10
	}

	length := minlength + gen.Rand.IntN(maxlength-minlength)
	content, ok := gen.FileCache[path]
	if !ok {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer file.Close()
		byteContent, err := io.ReadAll(file)
		if err != nil {
			return "", err
		}
		content = string(byteContent)
		if !utf8.ValidString(content) {
			return "", ErrInvalidString
		}
		gen.FileCache[path] = content
	}

	// Correctly trim by UTF-8 runes
	trimmed := []rune(content)
	if len(trimmed) < length {
		length = len(trimmed)
	}
	trimmed = trimmed[:length]
	return string(trimmed), nil
}
