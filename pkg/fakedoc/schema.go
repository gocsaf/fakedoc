// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021, 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021, 2024 Intevation GmbH <https://intevation.de>

// Package fakedoc contains code to generate random fake CSAF files
package fakedoc

import (
	"bytes"
	_ "embed" // Used for embedding.
	"io"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schema/csaf_json_schema.json
var csafSchema []byte

//go:embed schema/cvss-v2.0.json
var cvss20 []byte

//go:embed schema/cvss-v3.0.json
var cvss30 []byte

//go:embed schema/cvss-v3.1.json
var cvss31 []byte

type compiledSchema struct {
	url      string
	once     sync.Once
	err      error
	compiled *jsonschema.Schema
}

const (
	csafSchemaURL   = "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"
	cvss20SchemaURL = "https://www.first.org/cvss/cvss-v2.0.json"
	cvss30SchemaURL = "https://www.first.org/cvss/cvss-v3.0.json"
	cvss31SchemaURL = "https://www.first.org/cvss/cvss-v3.1.json"
)

var (
	compiledCSAFSchema = compiledSchema{url: csafSchemaURL}
)

// loadURL loads the content of an URL from embedded data or
// falls back to the global loader function of the jsonschema package.
func loadURL(s string) (io.ReadCloser, error) {
	loader := func(data []byte) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	switch s {
	case csafSchemaURL:
		return loader(csafSchema)
	case cvss20SchemaURL:
		return loader(cvss20)
	case cvss30SchemaURL:
		return loader(cvss30)
	case cvss31SchemaURL:
		return loader(cvss31)
	default:
		return jsonschema.LoadURL(s)
	}
}

func (cs *compiledSchema) compile() {
	c := jsonschema.NewCompiler()
	c.AssertFormat = true
	c.ExtractAnnotations = true
	c.LoadURL = loadURL
	cs.compiled, cs.err = c.Compile(cs.url)
}

func (cs *compiledSchema) getSchema() (*jsonschema.Schema, error) {
	cs.once.Do(cs.compile)
	return cs.compiled, cs.err
}

// CompileSchema compiles and returns the JSON schema for CSAF
func CompileSchema() (*jsonschema.Schema, error) {
	return compiledCSAFSchema.getSchema()
}
