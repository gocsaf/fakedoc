// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import (
	"math/rand/v2"
	"regexp"
	"regexp/syntax"
	"testing"
)

func TestPatternGeneratesMatchingStrings(t *testing.T) {
	regexps := []string{
		"",
		"a",
		"a*",
		"(abc|def)",
		"[0-9][0-9][a-zA-Z]+",
		".{10,20}",
		"^xy?z$",
	}
	rand := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))

	for _, re := range regexps {
		pattern, err := CompileRegexp(re)
		if err != nil {
			t.Fatalf("CompileRegexp(%q) failed: %v", re, err)
		}
		s := pattern.Sample(rand)
		ok, err := regexp.MatchString(re, s)
		if err != nil {
			t.Errorf("MatchString(%q, %q) failed: %v", re, s, err)
		}
		if !ok {
			t.Errorf("%q does not match generated string %q", re, s)
		}
	}
}

func TestCompileRegexpFeatureCheck(t *testing.T) {
	unsupportedPatterns := []struct {
		re string
		op syntax.Op
	}{
		{"a\\bx", syntax.OpWordBoundary},
		{"a\\Bx", syntax.OpNoWordBoundary},
	}
	for _, unsupported := range unsupportedPatterns {
		_, err := CompileRegexp(unsupported.re)
		if err == nil {
			t.Errorf(
				"CompileRegexp(%q) succeeded, expected failure due to %v",
				unsupported.re, unsupported.op,
			)
		}
	}
}
