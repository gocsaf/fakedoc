// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

// Implements a command line tool that generates a default template for
// the CSAF generator
package main

import (
	"log"
	"os"

	"github.com/gocsaf/fakedoc/pkg/fakedoc"
)

func main() {
	schema, err := fakedoc.CompileSchema()
	if err != nil {
		log.Fatalf("%v", err)
	}

	template, err := fakedoc.FromSchema(schema)
	if err != nil {
		log.Fatalf("%v", err)
	}
	template.Write(os.Stdout)
}