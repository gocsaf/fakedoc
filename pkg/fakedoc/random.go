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

// chooseK returns a slice of K different randomly chosen elements of
// choices. Assumes that choices has at least K elements and that all
// elements are different.
func chooseK[T any](rand *rand.Rand, k int, choices []T) []T {
	perm := rand.Perm(len(choices))
	chosen := make([]T, k)
	for i := range k {
		chosen[i] = choices[perm[i]]
	}
	return chosen
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
	"seed doesn't match format 'pcg:<1-16 hex digits>:<1-16 hex digits>'",
)

var seedPattern = regexp.MustCompile("^pcg:([0-9a-fA-F]{1,16}):([0-9a-fA-F]{1,16})$")

// ParseSeed parses a seed from a string and returns the resulting
// random number generator
func ParseSeed(seed string) (*rand.Rand, error) {
	matches := seedPattern.FindStringSubmatch(seed)
	if matches == nil {
		return nil, ErrSeedFormat
	}
	s1, err1 := strconv.ParseUint(matches[1], 16, 64)
	s2, err2 := strconv.ParseUint(matches[2], 16, 64)
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	return rand.New(rand.NewPCG(s1, s2)), nil
}
