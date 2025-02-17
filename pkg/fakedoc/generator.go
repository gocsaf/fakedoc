// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
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
// It is based on ErrBranchAbandoned
var ErrNoValidValue = fmt.Errorf("%w: could not generate valid value", ErrBranchAbandoned)

// ErrInvalidString is returned as error by the generator if the input
// text is not valid UTF-8. This can happen if the input is a binary
// file not a text document.
var ErrInvalidString = errors.New("not valid utf-8")

// Generator is the type of CSAF document generators
type Generator struct {
	Template        *Template
	Limits          *Limits
	SizeFactor      float64
	ForceMaxSize    bool
	RequireRegex    *regexp.Regexp
	Rand            *rand.Rand
	FileCache       map[string]string
	NameSpaces      map[string]*NameSpace
	snapshotTime    uint64
	namespaceIDErrs map[string]error
}

type namespaceSnapshot struct {
	valuesLen int
	refsLen   int
	time      uint64
}

// NameSpace helps implement TmplID and TmplRef by collecting the IDs
// and references for a name space. It holds both values and references
// so that the references can be set to actually existing IDs once all
// IDs have been generated
type NameSpace struct {
	Values    []string
	Refs      []*reference
	snapshots []namespaceSnapshot
	created   uint64
}

// namespacePool helps to recycle namespaces.
var namespacePool = sync.Pool{
	New: func() any { return new(NameSpace) },
}

func (ns *NameSpace) snapshot(time uint64) {
	var add bool // only take a new snapshot if something has changed.
	if n := len(ns.snapshots); n == 0 {
		add = true
	} else {
		last := &ns.snapshots[n-1]
		add = last.refsLen != len(ns.Refs) || last.valuesLen != len(ns.Values)
	}
	if add {
		ns.snapshots = append(ns.snapshots, namespaceSnapshot{
			time:      time,
			valuesLen: len(ns.Values),
			refsLen:   len(ns.Refs),
		})
	}
}

func (ns *NameSpace) restoreSnapshot(time uint64) {
	for i := len(ns.snapshots) - 1; i >= 0; i-- {
		s := &ns.snapshots[i]
		if s.time < time {
			break
		}
		clear(ns.Values[s.valuesLen:])
		ns.Values = ns.Values[:s.valuesLen]
		clear(ns.Refs[s.refsLen:])
		ns.Refs = ns.Refs[:s.refsLen]
		ns.snapshots = ns.snapshots[:i]
	}
}

func (gen *Generator) snapshotNamespaces() uint64 {
	old := gen.snapshotTime
	gen.snapshotTime++
	for _, ns := range gen.NameSpaces {
		ns.snapshot(old)
	}
	return old
}

func (gen *Generator) restoreNamespaceSnapshot(time uint64) {
	for name, ns := range gen.NameSpaces {
		if ns.created > time {
			// It wasn't there when taken.
			delete(gen.NameSpaces, name)
			// Recyle it as they are created frequently.
			*ns = NameSpace{}
			namespacePool.Put(ns)
		} else {
			ns.restoreSnapshot(time)
		}
	}
	gen.snapshotTime = time
}

func (ns *NameSpace) addValue(v string) {
	ns.Values = append(ns.Values, v)
}

func (ns *NameSpace) addRef(r *reference) {
	ns.Refs = append(ns.Refs, r)
}

// reference is the value of a node created for TmplRef or arrays of
// TmplRef during generation. In the former case it represents a single
// reference serialized to JSON as a JSON string. In the latter case
// it's a slice of references serialized as a JSON array of strings.
// The length field indicates which variant it is.
type reference struct {
	Namespace string
	// Length is less than zero to indicate a single reference, greater
	// or equal to zero to indicate an array
	Length int
	Values []string
}

func (ref *reference) MarshalJSON() ([]byte, error) {
	if ref.Length < 0 {
		return json.Marshal(ref.Values[0])
	}
	return json.Marshal(ref.Values)
}

// NewGenerator creates a new Generator based on a Template and an
// optional random number generator. If the random number generator is
// nil, a random number generator with a random seed will be used.
// Limits is an optional limits guidance.
func NewGenerator(
	tmpl *Template,
	limits *Limits,
	sizeFactor float64,
	forceMaxSize bool,
	rng *rand.Rand,
	requireRegex *regexp.Regexp,
) *Generator {
	if rng == nil {
		seed1, seed2 := rand.Uint64(), rand.Uint64()
		fmt.Fprintf(os.Stderr, "pcg:%x:%x\n", seed1, seed2)
		rng = rand.New(rand.NewPCG(seed1, seed2))
	}
	return &Generator{
		Template:        tmpl,
		Limits:          limits,
		SizeFactor:      sizeFactor,
		ForceMaxSize:    forceMaxSize,
		Rand:            rng,
		RequireRegex:    requireRegex,
		FileCache:       map[string]string{},
		NameSpaces:      map[string]*NameSpace{},
		namespaceIDErrs: map[string]error{},
	}
}

func (gen *Generator) getNamespace(name string) *NameSpace {
	ns := gen.NameSpaces[name]
	if ns == nil {
		ns = namespacePool.Get().(*NameSpace)
		ns.created = gen.snapshotTime
		gen.NameSpaces[name] = ns
	}
	return ns
}

// addNSValue adds a value to a namespace
func (gen *Generator) addNSValue(namespace, v string) {
	gen.getNamespace(namespace).addValue(v)
}

// adNSRef adds a reference to a namespace
func (gen *Generator) adNSRef(namespace string, r *reference) {
	gen.getNamespace(namespace).addRef(r)
}

func (gen *Generator) hasNSValues(namespace string) bool {
	return len(gen.getNamespace(namespace).Values) > 0
}

func (gen *Generator) numNSValues(namespace string) int {
	return len(gen.getNamespace(namespace).Values)
}

// Generate generates a document
func (gen *Generator) Generate() (any, error) {
	limits := gen.Limits.ArrayLimits()
	doc, err := gen.generateNode(gen.Template.Root, limits, 25)
	if err != nil {
		return nil, err
	}

	if err = gen.fixupReferences(); err != nil {
		return nil, err
	}

	return doc, nil
}

func (gen *Generator) generateNode(typename string, limits *LimitNode, depth int) (_ any, err error) {
	if depth <= 0 {
		return nil, ErrDepthExceeded
	}
	// make sure IDs generated in abandoned branches are discarded so
	// that we don't end up with e.g. references to group IDs that are
	// not actually there.
	snapshot := gen.snapshotNamespaces()
	defer func() {
		if errors.Is(err, ErrBranchAbandoned) {
			gen.restoreNamespaceSnapshot(snapshot)
		}
	}()
	if nodeTmpl := gen.Template.Types[typename]; nodeTmpl != nil {
		return nodeTmpl.Instantiate(gen, limits, depth)
	}
	return nil, fmt.Errorf("unknown type %q", typename)
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

func writeInt32(v int32, h hash.Hash64) {
	var buf [4]byte
	binary.NativeEndian.PutUint32(buf[:], uint32(v))
	h.Write(buf[:])
}

// hashing is used to create a 64 bit hash value for
// a generated item to speed up unique checks.
func hashing(v any, h hash.Hash64) {
	switch x := v.(type) {
	case string:
		io.WriteString(h, x)
	case []any:
		writeInt32(int32(len(x)), h)
		for _, y := range x {
			hashing(y, h)
		}
	case time.Time:
		if data, err := x.MarshalBinary(); err == nil {
			h.Write(data)
		}
	case *reference:
		io.WriteString(h, x.Namespace)
		writeInt32(int32(x.Length), h)
		writeInt32(int32(len(x.Values)), h)
		for _, y := range x.Values {
			io.WriteString(h, y)
		}
	case map[string]any:
		writeInt32(int32(len(x)), h)
		// keys := slices.Sorted(maps.Keys(x)) is slower!
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			io.WriteString(h, key)
			hashing(x[key], h)
		}
	default:
		panic(fmt.Sprintf("unkown type: %T", v))
	}
}

func (gen *Generator) randomArray(tmpl *TmplArray, limits *LimitNode, depth int) (any, error) {
	minitems := tmpl.MinItems
	maxitems := tmpl.MaxItems

	if minitems < 0 {
		minitems = 0
	}
	if maxitems < 0 {
		maxLimit := int(gen.SizeFactor * float64(limits.GetLimit()))
		maxitems = max(minitems, maxLimit)
	}

	if refnode, ok := gen.Template.Types[tmpl.Items].(*TmplRef); ok {
		known := gen.numNSValues(refnode.Namespace)
		if known >= minitems && tmpl.UniqueItems {
			ref := &reference{
				Namespace: refnode.Namespace,
				Length:    minitems + gen.Rand.IntN(known-minitems+1),
				Values:    nil,
			}
			gen.adNSRef(refnode.Namespace, ref)
			return ref, nil
		}
	}

	length := maxitems
	if !gen.ForceMaxSize {
		length = minitems + gen.Rand.IntN(maxitems-minitems+1)
	}

	var (
		items      []any
		hash       hash.Hash64
		hashes     map[uint64][]any
		key        uint64
		notInItems func(any) bool
	)

	if tmpl.UniqueItems {
		hashes = map[uint64][]any{}
		hash = fnv.New64()
		notInItems = func(v any) bool {
			hash.Reset()
			hashing(v, hash)
			key = hash.Sum64()
			return !slices.ContainsFunc(hashes[key], func(item any) bool {
				return reflect.DeepEqual(item, v)
			})
		}
	}

	for range length {
		item, err := gen.generateItemUntil(tmpl.Items, 10, limits, depth-1, notInItems)
		switch {
		case errors.Is(err, ErrNoValidValue):
			continue
		case err != nil:
			return nil, err
		}
		if items == nil {
			// We alloc the items slice here to tame the GC.
			// If we pre-alloc it before the loop and an error occurs
			// the GC is having a bad/hard time to free the memory as the
			// randomArray method is called at a high rate and the slices
			// tend to be large.
			// It is observed that the errors occur mainly with the
			// creation of the first item so we delay the allocation
			// after this point.
			items = make([]any, 0, length)
		}
		items = append(items, item)
		if hashes != nil {
			hashes[key] = append(hashes[key], item)
		}
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
	limits *LimitNode,
	depth int,
	cond func(any) bool,
) (any, error) {
	for range maxAttempts {
		item, err := gen.generateNode(typename, limits, depth-1)
		if err != nil {
			return nil, err
		}
		if cond == nil || cond(item) {
			return item, nil
		}
	}
	return nil, ErrNoValidValue
}

func (gen *Generator) randomOneOf(oneof []string, limits *LimitNode, depth int) (any, error) {
	shuffled := shuffle(gen.Rand, oneof)
	var abandoned error
	for _, typename := range shuffled {
		value, err := gen.generateNode(typename, limits, depth-1)
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

func (gen *Generator) forceRequired(property *Property) bool {
	return gen.RequireRegex != nil &&
		gen.RequireRegex.MatchString(property.Name)
}

func (gen *Generator) generateObject(node *TmplObject, limits *LimitNode, depth int) (any, error) {
	var optional, required []*Property
	for _, prop := range node.Properties {
		switch {
		case prop.Required || gen.forceRequired(prop):
			required = append(required, prop)
		default:
			optional = append(optional, prop)
		}
	}

	properties := make(map[string]any)
	for _, prop := range required {
		value, err := gen.generateNode(prop.Type, limits.Descend(prop.Name), depth-1)
		if err != nil {
			return nil, err
		}
		properties[prop.Name] = value
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
		value, err := gen.generateNode(prop.Type, limits.Descend(prop.Name), depth-1)
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

func (gen *Generator) generateID(namespace string) string {
	id := gen.randomString(1, 20)
	gen.addNSValue(namespace, id)
	return id
}

func (gen *Generator) generateReference(namespace string) (any, error) {
	if !gen.hasNSValues(namespace) {
		// These errors occur quiet often so it is cheaper
		// to cache them for reuse.
		err := gen.namespaceIDErrs[namespace]
		if err == nil {
			err = fmt.Errorf(
				"%w: no IDs in namespace %q", ErrBranchAbandoned, namespace)
			gen.namespaceIDErrs[namespace] = err
		}
		return nil, err
	}

	ref := &reference{
		Namespace: namespace,
		Length:    -1,
		Values:    nil,
	}
	gen.adNSRef(namespace, ref)
	return ref, nil
}

func (gen *Generator) fixupReferences() error {
	for name, ns := range gen.NameSpaces {
		if len(ns.Values) == 0 && len(ns.Refs) > 0 {
			// this should never happen because references should
			// only be generated if there are values available
			return fmt.Errorf(
				"no IDs when filling references in namespace %q",
				name,
			)
		}
		for _, ref := range ns.Refs {
			switch {
			case ref.Length < 0:
				ref.Values = []string{choose(gen.Rand, ns.Values)}
			case ref.Length == 0:
				ref.Values = nil
			default:
				ref.Values = chooseK(gen.Rand, ref.Length, ns.Values)
			}
		}
	}
	return nil
}
