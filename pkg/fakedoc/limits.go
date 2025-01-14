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

// LimitNode represents a node in the a tree representation of the
// limits.
type LimitNode struct {
	// Limit is the limit for the node
	Limit int
	// Branches maps the names of the children to the corresponding
	// nodes
	Branches map[string]*LimitNode
}

// NewLimitNode creates a new, empty node
func NewLimitNode() *LimitNode {
	return &LimitNode{
		Limit:    0,
		Branches: make(map[string]*LimitNode),
	}
}

func (ln *LimitNode) insert(path Path, limit int) {
	switch {
	case len(path) == 0:
		ln.Limit = limit
	default:
		node, ok := ln.Branches[path[0].Name]
		if !ok {
			node = NewLimitNode()
			ln.Branches[path[0].Name] = node
		}
		node.insert(path[1:], limit)
	}
}

// ArrayLimits builds a tree with the limits for the lentgths of arrays.
// This method can be called on nil, in which case it returns an empty
// LimitNode
func (lim *Limits) ArrayLimits() *LimitNode {
	node := NewLimitNode()
	if lim == nil {
		return node
	}
	for _, lp := range lim.ArrayLength {
		for _, path := range lp.Paths {
			node.insert(path, lp.Length)
		}
	}
	return node
}

// Descend returns the sub-tree for a child. This method can be called
// on nil, in which case it also returns nil.
func (ln *LimitNode) Descend(name string) *LimitNode {
	if ln == nil {
		return nil
	}
	return ln.Branches[name]
}

// GetLimit returns the limit associated with the node. It can be called
// on nil, in which case it returns 0.
func (ln *LimitNode) GetLimit() int {
	if ln == nil {
		return 0
	}
	return ln.Limit
}
