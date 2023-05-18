#!/usr/bin/env python
# encoding: utf-8

# This file is part of CycloneDX Python module.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) Steve Springett. All Rights Reserved.
# Copyright (c) 2023 OWASP Foundation. All Rights Reserved.


import argparse
from typing import Any
import csv
import json
import cyclonedx.model.bom

br_bom = cyclonedx.model.bom.Bom

# TODO Support component assemblies (if applicable to buildroot)
# TODO Support component dependencies
# TODO Support metadata\tools, metadata\component (if applicable), and any other metadata object or property

# Buildroot manifest.csv file header shows the following header row
# PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES
#

def create_buildroot_sbom(args, bom: br_bom):
    #
    # Capture the components that describe the complete inventory of first-party software
    final_component_details = list("")
    # Buildroot CSV file supplies software package data in each row. Any change to that map of data will break
    # the resulting JSON. Thus a try/except block to help with run time issues.
    with open(args.input_file, newline='') as csvfile:
        sheetX = csv.DictReader(csvfile)
        for row in sheetX:
            try:
                purl_info: str | Any = "pkg:generic/" + row['PACKAGE'] + "@" + row['VERSION'] + \
                                       "?download_url=" + row['SOURCE SITE'] + row['SOURCE ARCHIVE']
                license_list_info = list("")
                set_of_license_info = {"expression": row['LICENSE']}
                license_list_info.append(set_of_license_info)
                set_of_component_details = {"type": "library", "name": row['PACKAGE'], "version": row['VERSION'],
                                            "licenses": license_list_info, "purl": purl_info}
                final_component_details.append(set_of_component_details)
                from packageurl import PackageURL
                purl = PackageURL.from_string(purl_info)
                componenttype = cyclonedx.model.component.ComponentType('firmware')
                next_component = cyclonedx.model.component.Component(name=row['PACKAGE'],
                                                                     component_type=componenttype,
                                                                     purl=purl,
                                                                     licenses=row['LICENSE'],
                                                                     version=row['VERSION'])
                br_bom.add_component(next_component) #  parser.BaseParser._components.append(next_component)
            except KeyError:
                print("The input file header does not contain the expected data in the first row of the file.")
                print(
                    "Expected PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES")
                print("Found the following in the csv file first row:", row)
                print("Cannot continue with the provided input file. Exiting.")
                exit(-1)

def main():
    parser = argparse.ArgumentParser(description='CycloneDX BOM Generator')
    parser.add_argument('-i', action='store', dest='input_file', default='manifest.csv')
    parser.add_argument('-o', action='store', dest='output_file', default='export')
    parser.add_argument('-n', action='store', dest='input_name', default='unknown')
    parser.add_argument('-v', action='store', dest='component_version', default='unknown')

    args = parser.parse_args()
    print('Input file: ' + args.input_file)
    print('Output BOM: ' + args.output_file)
    print('SBOM Component Name: ' + args.input_name)
    print('SBOM Component Version: ' + args.component_version)

    # TODO update the author field to copy from the cli
    br_bom_Component = cyclonedx.model.bom.Component
    br_bom_Component(name="component name", version="1234", author="author",license_str="license",component_type='firmware')
    br_bom_Bom = cyclonedx.model.bom.Bom()
    br_bom_Bom.add_component(component=br_bom_Component)
    create_buildroot_sbom(args, br_bom)

    # Make the full BOM
    from cyclonedx.model.bom import Bom
    bom = Bom.from_parser(parser=br_parser)

    # Produce the output in pretty JSON format.
    from cyclonedx.output import get_instance, BaseOutput, OutputFormat
    outputter: BaseOutput = get_instance(bom=bom, output_format=OutputFormat.JSON)
    bom_json: str = outputter.output_as_string()
    outputfile = open((args.output_file + ".json"), mode='w')
    json.dump(json.loads(bom_json), outputfile, indent=3)
    outputfile.close()

    # Produce the output in XML format.
    outputterXML: BaseOutput = get_instance(bom=bom, output_format=OutputFormat.XML)
    bom_xml: str = outputterXML.output_to_file(filename=(args.output_file + ".onexml"), allow_overwrite=True)

    from xml.dom import minidom
    myxmldoc = minidom.parseString(open((args.output_file + ".onexml")).read())
    outputfile=open(args.output_file + ".xml", mode='w')
    print(myxmldoc.toprettyxml(), file=outputfile)
    outputfile.close()

main()
