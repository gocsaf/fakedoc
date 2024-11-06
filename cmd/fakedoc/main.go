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
	"flag"
	"log"
	"os"

	"github.com/gocsaf/fakedoc/pkg/fakedoc"
)

func main() {
	var templatefile string

	flag.StringVar(&templatefile, "template", "template.toml", "template file")
	flag.Parse()

	err := generate(templatefile)
	if err != nil {
		log.Fatal(err)
	}
}

func generate(templatefile string) error {
	templ, err := fakedoc.LoadTemplate(templatefile)
	if err != nil {
		return err
	}

	generator := fakedoc.NewGenerator(templ)
	csaf, err := generator.Generate()
	if err != nil {
		return err
	}
	return writeJSON(csaf)
}

func writeJSON(doc any) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	os.Stdout.Write(b)
	os.Stdout.WriteString("\n")
	return nil
}
