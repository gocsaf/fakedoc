// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

package fakedoc

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// PathEntry is an entry a path.
type PathEntry struct {
	Name      string
	Array     bool
	Recursive bool
}

// Path is a list of path entries.
type Path []PathEntry

// LengthPaths stores a length limits ans the paths which
// the limit should apply to.
type LengthPaths struct {
	Length int    `json:"length"`
	Paths  []Path `json:"paths"`
}

// Limits represents a limits file.
type Limits struct {
	FileSize    int64         `json:"file_size"`
	ArrayLength []LengthPaths `json:"arrays"`
	Strings     []LengthPaths `json:"strings"`
	URIs        []LengthPaths `json:"uris"`
}

var recursionRe = regexp.MustCompile(`\(/[^)]+\)\*`)

// UnmarshalText implements [encoding/TextUnmarshaler].
func (p *Path) UnmarshalText(text []byte) error {
	path := string(text)
	path = recursionRe.ReplaceAllStringFunc(path, func(s string) string {
		return s[1:len(s)-2] + "*"
	})
	es := strings.Split(path, "/")
	pentries := make(Path, 0, len(es))
	for _, e := range es {
		if e == "" {
			continue
		}
		a, recursive := strings.CutSuffix(e, "*")
		name, array := strings.CutSuffix(a, "[]")
		pentries = append(pentries, PathEntry{
			Name:      name,
			Recursive: recursive,
			Array:     array,
		})
	}
	*p = pentries
	return nil
}

// LoadLimitsFromReader loads a limits file from a reader.
func LoadLimitsFromReader(r io.Reader) (*Limits, error) {
	limits := new(Limits)
	if err := json.NewDecoder(r).Decode(limits); err != nil {
		return nil, err
	}
	return limits, nil
}

// LoadLimitsFromFile load a limits file from a file.
func LoadLimitsFromFile(fname string) (*Limits, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", fname, err)
	}
	defer f.Close()
	return LoadLimitsFromReader(f)
}
