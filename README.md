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

## Build

``` shell
go build -o fakedoc ./cmd/fakedoc
go build -o createtemplate ./cmd/createtemplate
```

To enable support for profiling with `go tool pprof`
to fakedoc add the build tag `profile`:

``` shell
go build -tags profile -o fakedoc ./cmd/fakedoc
```

## Usage

Generate a random CSAF document with default settings (with the `-o`
option for the output file, the tracking ID will match the filename):

``` shell
./fakedoc -o random-csaf.json
```

The generator can be influenced with a template. Create a template
containing all of the settings used by fakedoc with

``` shell
./createtemplate > template.toml
```

Use the template to generate a document:

``` shell
./fakedoc --template template.toml -o random-csaf.json
```

The template file is used in addition to the built-in template used when
the --template option is not given. See the
[template documentation](docs/templates.md) for details about the
templates.

Generate many documents at once with the `-n` option and an output
filename with a template for filenames. This will generate 100 documents
named `csaf-0.json` through `csaf-99.json`:

``` shell
./fakedoc --template template.toml -n 100 -o 'csaf-{{$}}.json'
```

To generate large documents, one can use the something like this:

``` shell
./fakedoc -o random-csaf.json -l limits.json --force-max-size
```

With the `-l limits.json` option, fakedoc loads information about the
maximum lengths of arrays, strings and URIs from the `limits.json` file.
If loaded the maximum lenghts of arrays are taken from this file (it's
only implemented for arrays so far). By default these maximum values are
multiplied by 0.00001 to avoid generating exceedingly large files. This
factor can be set with the `--size` option. With the `--force-max-size`
option, fakedoc tries to make arrays as large as their maximum length.

How big the files will actually be depends not only on the length of the
arrays but also on which parts of the document are actually generated.

## License

fakedoc is Free Software:

```
SPDX-License-Identifier: Apache-2.0

SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2024 Intevation GmbH <https://intevation.de>
```
