<!--
 This file is Free Software under the Apache-2.0 License
 without warranty, see README.md and LICENSES/Apache-2.0.txt for details.

 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2024 Intevation GmbH <https://intevation.de>
-->

# Fake CSAF document generator

Will allow the creation
of one or many fake CSAF 2.0 documents to explore
and test implementations of this standard.

Will use the CSAF Go library where appropriate.

## Usage

Generate a random CSAF document with default settings (with the `-o`
option for the output file, the tracking ID will match the filename):

``` shell
go run cmd/fakedoc/main.go -o random-csaf.json
```

The generator can be influenced with a template. Create a template
containing all of the settings used by fakedoc with

``` shell
go run cmd/createtemplate/main.go  > template.toml
```

Use the template to generate a document:

``` shell
go run cmd/fakedoc/main.go --template template.toml -o random-csaf.json
```

The template file is used in addition to the built-in template used when
the --template option is not given. See the
[template documentation](docs/templates.md) for details about the
templates.

Generate many documents at once with the `-n` option and an output
filename with a template for filenames. This will generate 100 documents
named `csaf-000.json` through `csaf-99.json`:

``` shell
go run cmd/fakedoc/main.go --template template.toml -n 100 -o 'csaf-{{$}}.json'
```



## License

fakedoc is Free Software:

```
SPDX-License-Identifier: Apache-2.0

SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2024 Intevation GmbH <https://intevation.de>
```
