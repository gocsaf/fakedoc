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
	"bytes"
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
	"text/template"

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

	numOutputDocumentation = `
How many documents to generate . If greate than 1, the output filename
must be given. It is treated as a template for filenames in which {{$}}
will be replaced with the number of the file, starting with 0.
`

	indentLengthDocumentation = `
How many spaces are used for indentation of the output file.
If omitted, the default value of 2 spaces is used.
`
)

func main() {
	var (
		templatefile string
		seed         string
		outputfile   string
		numOutputs   int
		indentLength int
	)

	flag.StringVar(&templatefile, "template", "", "template file")
	flag.StringVar(&seed, "seed", "", seedDocumentation)
	flag.StringVar(&outputfile, "o", "", outputDocumentation)
	flag.IntVar(&numOutputs, "n", 1, numOutputDocumentation)
	flag.IntVar(&indentLength, "i", 2, indentLengthDocumentation)
	flag.Parse()

	if numOutputs > 1 && outputfile == "" {
		log.Fatal("Multiple outputs require an explicit output file template")
	}

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

	err = generate(templatefile, rng, outputfile, numOutputs, indentLength)
	if err != nil {
		log.Fatal(err)
	}
}

func generate(templatefile string, rng *rand.Rand, outputfile string, numOutputs int, indentLength int) error {
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

	if numOutputs == 1 {
		return generateToFile(generator, outputfile, indentLength)
	}

	tmplFilename, err := template.New("filename").Parse(outputfile)
	if err != nil {
		return err
	}

	for n := range numOutputs {
		filename, err := makeFilename(tmplFilename, n)
		if err != nil {
			return err
		}
		err = generateToFile(generator, filename, indentLength)
		if err != nil {
			return err
		}
	}

	return nil
}

func makeFilename(tmpl *template.Template, n int) (string, error) {
	var filename bytes.Buffer

	err := tmpl.Execute(&filename, n)
	if err != nil {
		return "", err
	}
	return filename.String(), nil
}

func generateToFile(generator *fakedoc.Generator, outputfile string, indentLength int) error {
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
	return writeJSON(csaf, outputfile, indentLength)
}

func trackingIDFromFilename(filename string) (string, error) {
	base := filepath.Base(filename)
	id, found := strings.CutSuffix(base, ".json")
	if !found {
		return "", fmt.Errorf("filename %q doesn't have .json suffix", filename)
	}
	return id, nil
}

func writeJSON(doc any, outputfile string, indentLength int) error {
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
	indent := strings.Repeat(" ", indentLength)
	enc.SetIndent("", indent)
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
