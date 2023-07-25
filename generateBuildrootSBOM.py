# encoding: utf-8

# This file is part of CycloneDX Buildroot module.
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
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2023 OWASP Foundation. All Rights Reserved.

import argparse
import csv
import json
import sys

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import OrganizationalEntity
from cyclonedx.output import get_instance, BaseOutput, OutputFormat
from xml.dom import minidom


# Buildroot manifest.csv file header shows the following header row
# PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES
#
def create_buildroot_sbom(input_file_name: str, br_bom: Bom):
    br_bom_local: Bom = br_bom
    #
    # Capture the components that describe the complete inventory of first-party software
    # Buildroot CSV file supplies software package data in each row. Any change to that map of data will break
    # the resulting JSON. Use a try/except block to help with run time issues.
    with open(input_file_name, newline='') as csvfile:
        sheetX = csv.DictReader(csvfile)

        for row in sheetX:
            try:

                purl_info = PackageURL(type='generic', name=row['PACKAGE'], version=row['VERSION'],
                                       qualifiers={'download_url': row['SOURCE SITE'] + row['SOURCE ARCHIVE']})
                lfac = LicenseFactory()

                next_component = Component(name=row['PACKAGE'],
                                           type=ComponentType.FIRMWARE,
                                           licenses=[lfac.make_from_string(row['LICENSE'])],
                                           version=row['VERSION'],
                                           purl=purl_info,
                                           bom_ref=row['PACKAGE'])

                br_bom_local.components.add(next_component)
                br_bom_local.register_dependency(br_bom.metadata.component, [next_component])
            except KeyError:
                print("The input file header does not contain the expected data in the first row of the file.")
                print(
                    "Expected PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES")
                print("Found the following in the csv file first row:", row)
                print("Cannot continue with the provided input file. Exiting.")
                exit(-1)

    return br_bom_local


def my_main(*args):
    parser = argparse.ArgumentParser(description='CycloneDX BOM Generator')
    parser.add_argument('-i', action='store', dest='input_file', default='manifest.csv',
                        help='comma separated value (csv) file of buildroot manifest data')
    parser.add_argument('-o', action='store', dest='output_file', default='buildroot_IOT_sbom',
                        help='SBOM output file name for json and xml')
    parser.add_argument('-n', action='store', dest='product_name', default='unknown', help='name of the product')
    parser.add_argument('-v', action='store', dest='product_version', default='unknown', help='product version string')
    parser.add_argument('-m', action='store', dest='manufacturer_name', default='unknown',
                        help='name of product manufacturer')
    if (len(args) != 0):
        unittest_args = list(args)
        args = parser.parse_args(list(args))
    else:
        args = parser.parse_args()

    print('Buildroot manifest input file: ' + args.input_file)
    print('Output SBOM: ' + args.output_file)
    print('SBOM Product Name: ' + args.manufacturer_name)
    print('SBOM Product Version: ' + args.product_version)
    print('SBOM Product Manufacturer: ' + args.manufacturer_name)

    br_bom = Bom()
    br_bom.metadata.component = rootComponent = Component(name=args.product_name,
                                                          version=args.product_version,
                                                          bom_ref=args.product_name)
    br_meta = BomMetaData(manufacture=OrganizationalEntity(name=args.manufacturer_name),
                          component=rootComponent)
    br_bom.metadata = br_meta

    br_bom = create_buildroot_sbom(str(args.input_file).strip(" "), br_bom)

    # Produce the output in pretty JSON format.
    outputter: BaseOutput(bom=br_bom) = get_instance(bom=br_bom, output_format=OutputFormat.JSON)
    bom_json = outputter.output_as_string()
    outputfile = open((args.output_file + ".json"), mode='w')
    json.dump(json.loads(bom_json), outputfile, indent=3)
    outputfile.close()

    # Produce the output in XML format that is in a one-line format.
    outputterXML: BaseOutput(bom=br_bom) = get_instance(bom=br_bom, output_format=OutputFormat.XML)
    outputterXML.output_to_file(filename=(args.output_file + ".one.xml"), allow_overwrite=True)

    # Produce the output in XML format that is indented format.
    myxmldocfile = open((args.output_file + ".one.xml"))
    myxmldoc = minidom.parseString(myxmldocfile.read())
    outputfile = open(args.output_file + ".xml", mode='w')
    print(myxmldoc.toprettyxml(), file=outputfile)
    outputfile.close()
    myxmldocfile.close()

if __name__ == "__main__":
    my_main()
