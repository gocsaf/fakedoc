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
	"math/rand/v2"
	"regexp"
	"strconv"
)

// choose returns a random element of choices. The element is chosen
// with uniform distribution. The choices slice must not be empty.
func choose[T any](rand *rand.Rand, choices []T) T {
	return choices[rand.IntN(len(choices))]
}

// shuffle randomly shuffles a slice
func shuffle[T any](rand *rand.Rand, ts []T) []T {
	rand.Shuffle(len(ts), func(i, j int) {
		ts[i], ts[j] = ts[j], ts[i]
	})
	return ts
}

// ErrSeedFormat is the error returned by ParseSeed for incorrectly
// formatted seed values.
var ErrSeedFormat = errors.New(
	"seed doesn't match format 'pcg:<1-8 hex digits>:<1-8 hex digits>'",
)

var seedPattern = regexp.MustCompile("^pcg:([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,8})$")

// ParseSeed parses a seed from a string and returns the resulting
// random number generator
func ParseSeed(seed string) (*rand.Rand, error) {
	matches := seedPattern.FindAllStringSubmatch(seed, -1)
	if len(matches) == 0 {
		return nil, ErrSeedFormat
	}
	s1, err := strconv.ParseUint(matches[0][1], 16, 64)
	if err != nil {
		return nil, err
	}
	s2, err := strconv.ParseUint(matches[0][2], 16, 64)
	if err != nil {
		return nil, err
	}

	return rand.New(rand.NewPCG(s1, s2)), nil
}
