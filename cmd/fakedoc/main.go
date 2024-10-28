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
	"log"
	"os"

	"github.com/gocsaf/fakedoc/pkg/fakedoc"
)

func main() {
	templatefile := "template.toml"
	if len(os.Args) > 1 {
		templatefile = os.Args[1]
	}

	templ, err := fakedoc.LoadTemplate(templatefile)
	if err != nil {
		log.Fatal(err)
	}

	generator := fakedoc.NewGenerator(templ)
	csaf, err := generator.Generate()
	if err != nil {
		log.Fatal(err)
	}
	writeJSON(csaf)
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
