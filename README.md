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

## Usage

By default, `manifest.csv` will be read from the current working directory
and the resulting `bom.json` will also be created in the current working directory.  
This can be overwritten as follows:

```ShellSession

  
$ python3 generateBuildrootSBOM.py -i <path>/manifest.csv -n "My Project" -v "1.2.3.4" -m "company name" -c cpe.json
      Usage:  generateBom.cli [OPTIONS]
      Options:
        -i <path> - filename of the output from make legal-info, example: manifest.csv
        -o <path> - the bom file name to create
        -n name of the project or product SBOM <project name in quotes>
        -v your product SBOM version <project version in quotes>
        -m SBOM manufacturer name
        -c <path> - cpe file name from make show-info, example cpe.json
```

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

## Copyright & License

CycloneDX Buildroot is Copyright (c) OWASP Foundation. All Rights Reserved.  
Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE file][License] for the full license.

[CDX_homepage]: https://cyclonedx.org
[License]: https://github.com/CycloneDX/cyclonedx-buildroot/blob/main/LICENSE
[Buildroot_homepage]: https://buildroot.org
