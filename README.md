[![Build Status](https://github.com/CycloneDX/cyclonedx-buildroot/workflows/CI/badge.svg)](https://github.com/CycloneDX/cyclonedx-buildroot/actions?workflow=CI)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)][License]  
[![Website](https://img.shields.io/badge/https://-cyclonedx.org-blue.svg)][CDX_homepage]
[![Slack Invite](https://img.shields.io/badge/Slack-Join-blue?logo=slack&labelColor=393939)](https://cyclonedx.org/slack/invite)
[![Group Discussion](https://img.shields.io/badge/discussion-groups.io-blue.svg)](https://groups.io/g/CycloneDX)
[![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&label=Follow)](https://twitter.com/CycloneDX_Spec)

----

# CycloneDX Buildroot

This [Buildroot][Buildroot_homepage] python application generates [CycloneDX][CDX_homepage] Software Bill of Materials 
(SBOM) containing all direct dependencies of a Buildroot generated project.  
OWASP CycloneDX is a full-stack Bill of Materials (BOM) standard that provides advanced supply chain capabilities for 
cyber risk reduction.
Buildroot provides a build target named "legal-info" which produces a set of files including manifest.csv. The legal-info
is a general "make" target for a Buildroot project.

## Requirements

* `python >= 3.8`

## Installation

Install this from [Python Package Index (PyPI)][link_pypi] using your preferred Python package manager.

install via one of commands:

```shell
python -m pip install cyclonedx-buildroot   # install via pip
pipx install cyclonedx-buildroot            # install via pipx
poetry add cyclonedx-buildroot              # install via poetry
uv tool install cyclonedx-buildroot         # install via uv
# ... you get the hang
````

## Usage

Call via one of commands:

```shell
cyclonedx-buildroot            # call script
python -m cyclonedx_buildroot  # call python module CLI
```

### Help page

```shellSession
$ cyclonedx-buildroot --help
usage: cyclonedx-buildroot [-h] [-i INPUT_FILE] [-o OUTPUT_FILE] [-n PRODUCT_NAME] [-v PRODUCT_VERSION] [-m MANUFACTURER_NAME] [-c CPE_INPUT_FILE]

CycloneDX BOM Generator

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE         comma separated value (csv) file of buildroot manifest data
  -o OUTPUT_FILE        SBOM output file name for json and xml
  -n PRODUCT_NAME       name of the product
  -v PRODUCT_VERSION    product version string
  -m MANUFACTURER_NAME  name of product manufacturer
  -c CPE_INPUT_FILE     cpe file from make show-info
```

### Example

By default, `manifest.csv` will be read from the current working directory
and the resulting `bom.json` will also be created in the current working directory.  
This can be overwritten as follows:

```shell
cyclonedx-buildroot -i <path>/manifest.csv -n "My Project" -v "1.2.3.4" -m "company name" -c cpe.json
```

## Integration

Diagram depicting where this project fits into the pipeline of secure development activities. Note that while the diagram depicts a linear sequence of
activities, the entire sequence is typically cyclical. The end state of SBOM management receives the SBOM files for the product versions to properly
manage the state of vulnerabilities over time. 

![CycloneDX logo](https://github.com/CycloneDX/cyclonedx-buildroot/blob/main/build-Page-2.drawio.png)

## CycloneDX Schema Support

The following table provides information on the version of this module, the CycloneDX schema version supported, as well as the output format options.
Use the latest possible version of this module that is compatible with the CycloneDX version supported by the target system.

| Version | Schema Version | Format(s) |
|---------|----------------|-----------|
| 1.0x | CycloneDX v1.4 | XML/JSON |

## Internals

This tool utilizes the [CycloneDX Python library][cyclonedx-library] to generate the actual data structures, and serialize and validate them.

This tool does **not** expose any additional _public_ API or symbols - all code is intended to be internal and might change without any notice during version upgrades.  
However, the CLI is stable - you might call it programmatically like so:
```python
from sys import executable
from subprocess import run
run((executable, '-m', 'cyclonedx_buildroot', '--help'))
```

## Copyright & License

CycloneDX Buildroot is Copyright (c) OWASP Foundation. All Rights Reserved.  
Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE file][License] for the full license.

[CDX_homepage]: https://cyclonedx.org
[License]: https://github.com/CycloneDX/cyclonedx-buildroot/blob/main/LICENSE
[Buildroot_homepage]: https://buildroot.org
[link_pypi]: https://pypi.org/project/CycloneDX-Buildroot/
