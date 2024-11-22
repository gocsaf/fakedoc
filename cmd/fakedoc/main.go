// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

// Implements a command line tool that generates a random CSAF file
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocsaf/fakedoc/pkg/fakedoc"
)

const (
	seedDocumentation = `
random number seed, format 'pcg:<1-8 hex digits>:<1-8 hex digits>'.
If omitted, the generator uses a random seed.
`

	outputDocumentation = `
output filename. Setting this will also set the tracking ID in the
generated file so that it matches the filename. The filename must end
with '.json'
`
)

func main() {
	var (
		templatefile string
		seed         string
		outputfile   string
	)

	flag.StringVar(&templatefile, "template", "template.toml", "template file")
	flag.StringVar(&seed, "seed", "", seedDocumentation)
	flag.StringVar(&outputfile, "o", "", outputDocumentation)
	flag.Parse()

	var (
		rng *rand.Rand
		err error
	)
	if seed != "" {
		rng, err = fakedoc.ParseSeed(seed)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = generate(templatefile, rng, outputfile)
	if err != nil {
		log.Fatal(err)
	}
}

func generate(templatefile string, rng *rand.Rand, outputfile string) error {
	templ, err := fakedoc.FromCSAFSchema()
	if err != nil {
		return err
	}

	if templatefile != "" {
		overrides, err := fakedoc.LoadTemplate(templatefile)
		if err != nil {
			return err
		}
		templ.Merge(overrides)
	}

	generator := fakedoc.NewGenerator(templ, rng)
	csaf, err := generator.Generate()
	if err != nil {
		return err
	}

	if outputfile != "" {
		id, err := trackingIDFromFilename(outputfile)
		if err != nil {
			return err
		}
		if err := setValue(csaf, "document/tracking/id", id); err != nil {
			return fmt.Errorf("setting tracking ID: %w", err)
		}
	}
	return writeJSON(csaf, outputfile)
}

func trackingIDFromFilename(filename string) (string, error) {
	base := filepath.Base(filename)
	id, found := strings.CutSuffix(base, ".json")
	if !found {
		return "", fmt.Errorf("filename %q doesn't have .json suffix", filename)
	}
	return id, nil
}

func writeJSON(doc any, outputfile string) error {
	var out io.Writer = os.Stdout
	var file *os.File
	if outputfile != "" {
		var err error
		if file, err = os.Create(outputfile); err != nil {
			return err
		}
		out = file
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	var err1, err2 error = enc.Encode(doc), nil
	if file != nil {
		err2 = file.Close()
	}
	return errors.Join(err1, err2)
}

func setValue(doc any, path string, value any) error {
	m, ok := doc.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any, got %T", doc)
	}

	components := strings.Split(path, "/")
	finalKey := components[len(components)-1]
	for i, key := range components[:len(components)-1] {
		value, ok := m[key]
		if !ok {
			return fmt.Errorf("path %q not in map", strings.Join(components[:i+1], "/"))
		}
		m, ok = value.(map[string]any)
		if !ok {
			return fmt.Errorf("path %q does not refer to a map", strings.Join(components[:i+1], "/"))
		}
	}
	m[finalKey] = value

	return nil
}
