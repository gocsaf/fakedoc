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

Create a template with

``` go
go run cmd/createtemplate/main.go  > template.toml
```

Use the template to generate a document. The document is written to stdout

``` go
go run cmd/fakedoc/main.go template.toml
```

## License

fakedoc is Free Software:

```
SPDX-License-Identifier: Apache-2.0

SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2024 Intevation GmbH <https://intevation.de>
```
