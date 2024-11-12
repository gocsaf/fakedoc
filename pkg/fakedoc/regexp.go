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
	"regexp/syntax"
	"strings"
)

// Pattern generates strings based on a regular expression
type Pattern struct {
	// the original regular expression
	Pattern string
	// The AST of the regular expression
	ast *syntax.Regexp
}

// CompileRegexp converts a string with a regular expression into a
// Pattern. In addition to parsing the regular expression it also checks
// whether the pattern only uses features that the random match
// generator supports.
func CompileRegexp(unparsed string) (*Pattern, error) {
	var pat Pattern
	if err := pat.UnmarshalText([]byte(unparsed)); err != nil {
		return nil, err
	}
	return &pat, nil
}

// UnmarshalText implements the TextUnmarshaler interface
func (pat *Pattern) UnmarshalText(text []byte) error {
	unparsed := string(text)
	ast, err := syntax.Parse(unparsed, syntax.Perl)
	if err != nil {
		return err
	}

	if err = checkAst(ast); err != nil {
		return err
	}

	pat.Pattern = unparsed
	pat.ast = ast
	return nil
}

// Sample generates a random match for the regular expression in Pattern
//
// The generator is not perfect, but should handle handle the regexps found
// in the CSAF JSON schema. Known limitations:
//
//   - ^ and $ are effectively ignored. This means that the code will
//     produce strings even for regexps that don't have any matches at
//     all, like e.g. a^b, which results in the incorrect "ab". Also,
//     even when matching strings exist, it may produce non-matching
//     strings. For example a*^b matches "b" but the generater might
//     produce "ab" anyway.
//
//   - The go regexp library supports more features than the generator
//     can handle so far.
func (pat *Pattern) Sample(rand *rand.Rand) string {
	var buf strings.Builder
	sampler := sampler{rand: rand, buf: &buf}
	sampler.sampleAstNode(pat.ast)
	return buf.String()
}

type sampler struct {
	rand *rand.Rand
	buf  *strings.Builder
}

func (s *sampler) sampleAstNode(ast *syntax.Regexp) {
	switch ast.Op {
	case syntax.OpAlternate:
		s.sampleAstNode(choose(s.rand, ast.Sub))
	case syntax.OpAnyCharNotNL:
		// FIXME: choose better character range
		s.buf.WriteRune(s.chooseCharClass([]rune{' ', '\x7e'}))
	case syntax.OpBeginText:
		// FIXME: check we're actually at the beginning of the text
	case syntax.OpCapture:
		s.sampleAstNode(ast.Sub[0])
	case syntax.OpCharClass:
		// FIXME: do not assume that re.Rune is not empty (can happen
		// for e.g. [^\x00-\x{10FFFF}])
		s.buf.WriteRune(s.chooseCharClass(ast.Rune))
	case syntax.OpConcat:
		for _, sub := range ast.Sub {
			s.sampleAstNode(sub)
		}
	case syntax.OpEmptyMatch:
		// nothing to be done
	case syntax.OpEndText:
		// FIXME: check we're actually at the end of the text.
	case syntax.OpLiteral:
		s.buf.WriteString(string(ast.Rune))
	case syntax.OpPlus:
		s.repeat(ast.Sub[0], s.chooseRange(1, 10))
	case syntax.OpQuest:
		if s.rand.IntN(2) > 0 {
			s.sampleAstNode(ast.Sub[0])
		}
	case syntax.OpRepeat:
		s.repeat(ast.Sub[0], s.chooseRange(ast.Min, ast.Max))
	case syntax.OpStar:
		s.repeat(ast.Sub[0], s.chooseRange(0, 10))
	default:
		// We should never get here. Unsupported operations should have
		// been found by checkAst
	}
}

func (s *sampler) chooseCharClass(runes []rune) rune {
	count := 0
	for i := 0; i < len(runes); i += 2 {
		count += int(runes[i+1] - runes[i] + 1)
	}
	choice := s.rand.IntN(count)
	for i := 0; i < len(runes); i += 2 {
		start := int(runes[i])
		end := int(runes[i+1])
		length := end - start + 1
		if choice < length {
			return rune(start + choice)
		}
		choice -= length
	}

	// unreachable
	return 0
}

func (s *sampler) repeat(re *syntax.Regexp, count int) {
	for range count {
		s.sampleAstNode(re)
	}
}

func (s *sampler) chooseRange(low, high int) int {
	if high < 0 {
		// no upper bound given in the regex. Choose an fixed arbitray
		// upper bound anyway to avoid excessively long strings
		high = low + 10
	}
	length := high - low
	if length > 0 {
		length = s.rand.IntN(length + 1)
	}
	return low + length
}

var supportedOps = map[syntax.Op]any{
	syntax.OpAlternate:    nil,
	syntax.OpAnyCharNotNL: nil,
	syntax.OpBeginText:    nil,
	syntax.OpCapture:      nil,
	syntax.OpCharClass:    nil,
	syntax.OpConcat:       nil,
	syntax.OpEmptyMatch:   nil,
	syntax.OpEndText:      nil,
	syntax.OpLiteral:      nil,
	syntax.OpPlus:         nil,
	syntax.OpQuest:        nil,
	syntax.OpRepeat:       nil,
	syntax.OpStar:         nil,
}

func checkAst(ast *syntax.Regexp) error {
	ops := map[syntax.Op]any{}
	err := checkAstNode(ast, &ops)
	if err != nil {
		return err
	}
	unsupported := []syntax.Op{}
	for op := range ops {
		if _, ok := supportedOps[op]; !ok {
			unsupported = append(unsupported, op)
		}
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("unsupported regexp operations: %v", unsupported)
	}
	return nil
}

func checkAstNode(ast *syntax.Regexp, ops *map[syntax.Op]any) error {
	(*ops)[ast.Op] = nil
	switch ast.Op {
	case syntax.OpAlternate, syntax.OpConcat:
		for _, sub := range ast.Sub {
			checkAstNode(sub, ops)
		}
	case syntax.OpCapture, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat, syntax.OpStar:
		checkAstNode(ast.Sub[0], ops)
	case syntax.OpCharClass:
		if len(ast.Rune) == 0 {
			return fmt.Errorf("character class without valid matches")
		}
	default:
		// nothing to do
	}
	return nil
}
