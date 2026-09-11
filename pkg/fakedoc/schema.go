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
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schema/csaf_json_schema_2.0.json
var csafSchema20 []byte

//go:embed schema/csaf_json_schema_2.1.json
var csafSchema21 []byte

//go:embed schema/csaf-meta.json
var csafMetaSchema []byte

//go:embed schema/cvss-v2.0.json
var cvss20 []byte

//go:embed schema/cvss-v3.0.json
var cvss30 []byte

//go:embed schema/cvss-v3.1.json
var cvss31 []byte

//go:embed schema/cvss-v4.0.json
var cvss40 []byte

//go:embed schema/cvss-meta.json
var cvssMeta []byte

//go:embed schema/SelectionList_2_0_0.schema.json
var selectionListSchema []byte

type compiledSchema struct {
	url      string
	once     sync.Once
	err      error
	compiled *jsonschema.Schema
}

const (
	csaf20SchemaURL           = "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"
	csaf21SchemaURL           = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json"
	csaf21ExtensionContentURL = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/extension-content.json"
	csafMetaSchemaURL         = "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/meta.json"
	cvss20SchemaURL           = "https://www.first.org/cvss/cvss-v2.0.json"
	cvss30SchemaURL           = "https://www.first.org/cvss/cvss-v3.0.json"
	cvss31SchemaURL           = "https://www.first.org/cvss/cvss-v3.1.json"
	cvss40SchemaURL           = "https://www.first.org/cvss/cvss-v4.0.json"
	cvssMetaSchemaURL         = "https://www.first.org/cvss/meta.json"
	selectionListSchemaURL    = "https://certcc.github.io/SSVC/data/schema/v2/SelectionList_2_0_0.schema.json"
)

var (
	compiledCSAFSchema20 = compiledSchema{url: csaf20SchemaURL}
	compiledCSAFSchema21 = compiledSchema{url: csaf21SchemaURL}
)

// loadURL loads the content of an URL from embedded data or
// falls back to the global loader function of the jsonschema package.
func loadURL(s string) (io.ReadCloser, error) {
	loader := func(data []byte) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	switch s {
	case csaf20SchemaURL:
		return loader(csafSchema20)
	case csaf21SchemaURL:
		return loader(csafSchema21)
	case csafMetaSchemaURL:
		return loader(csafMetaSchema)
	case csaf21ExtensionContentURL:
		return loader(csafSchema21)
	case cvss20SchemaURL:
		return loader(cvss20)
	case cvss30SchemaURL:
		return loader(cvss30)
	case cvss31SchemaURL:
		return loader(cvss31)
	case cvss40SchemaURL:
		return loader(cvss40)
	case cvssMetaSchemaURL:
		return loader(cvssMeta)
	case selectionListSchemaURL:
		return loader(selectionListSchema)
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
func CompileSchema20() (*jsonschema.Schema, error) {
	return compiledCSAFSchema20.getSchema()
}

// CompileSchema compiles and returns the JSON schema for CSAF
func CompileSchema21() (*jsonschema.Schema, error) {
	return compiledCSAFSchema21.getSchema()
}

// ShortLocation returns a shortened version of the schema's Location.
// In the shortened form the URL prefix is replaced with a much shorter
// prefix. The shortened form is still unique enough to identify
// subschemas for the purposes of fakedoc
func ShortLocation(schema *jsonschema.Schema) string {
	location := schema.Location
	for _, short := range shortPrefixes {
		if shortened, ok := strings.CutPrefix(location, short.prefix); ok {
			return short.short + ":" + shortened
		}
	}
	return location
}

var shortPrefixes = []struct{ short, prefix string }{
	{"csaf20", csaf20SchemaURL},
	{"csaf21", csaf21SchemaURL},
	{"cvss20", cvss20SchemaURL},
	{"cvss30", cvss30SchemaURL},
	{"cvss31", cvss31SchemaURL},
}
