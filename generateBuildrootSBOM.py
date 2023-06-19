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
import csv
import json

import cyclonedx
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import OrganizationalEntity
from cyclonedx.output import get_instance, BaseOutput, OutputFormat
from xml.dom import minidom


# TODO Support component assemblies (if applicable to buildroot)
# TODO Support component dependencies
# TODO Support metadata\tools, metadata\component (if applicable), and any other metadata object or property

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
                componenttype = cyclonedx.model.component.ComponentType.FIRMWARE
                lfac = LicenseFactory()
                next_component = cyclonedx.model.component.Component(name=row['PACKAGE'],
                                                                     type=componenttype,
                                                                     licenses=[lfac.make_from_string(row['LICENSE'])],
                                                                     version=row['VERSION'],
                                                                     purl=purl_info)
                br_bom_local.components.add(next_component)

            except KeyError:
                print("The input file header does not contain the expected data in the first row of the file.")
                print(
                    "Expected PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES")
                print("Found the following in the csv file first row:", row)
                print("Cannot continue with the provided input file. Exiting.")
                exit(-1)

    return br_bom_local


def my_main():
    parser = argparse.ArgumentParser(description='CycloneDX BOM Generator')
    parser.add_argument('-i', action='store', dest='input_file', default='manifest.csv')
    parser.add_argument('-o', action='store', dest='output_file', default='buildroot_IOT_sbom')
    parser.add_argument('-n', action='store', dest='input_name', default='unknown')
    parser.add_argument('-v', action='store', dest='component_version', default='unknown')

    args = parser.parse_args()
    print('Buildroot manifest input file: ' + args.input_file)
    print('Output SBOM: ' + args.output_file)
    print('SBOM Component Name: ' + args.input_name)
    print('SBOM Component Version: ' + args.component_version)

    # TODO provide a way to specify the metadata of this BOM using cyclonedx-python-lib v4.0.0 schema
    # need support to provide the user with the ability to specify the following for this BOM
    # authors
    # component
    # manufacture
    # license

    br_bom = Bom()
    new_bom = create_buildroot_sbom(args.input_file, br_bom)
    br_meta = BomMetaData(manufacture=OrganizationalEntity(name="Acme Inc"))
    new_bom.metadata = br_meta
    new_bom.version = args.component_version

    # Produce the output in pretty JSON format.
    outputter: BaseOutput(bom=new_bom) = get_instance(bom=new_bom, output_format=OutputFormat.JSON)
    bom_json = outputter.output_as_string()
    outputfile = open((args.output_file + ".json"), mode='w')
    json.dump(json.loads(bom_json), outputfile, indent=3)
    outputfile.close()

    # Produce the output in XML format that is in a one-line format.
    outputterXML: BaseOutput(bom=new_bom) = get_instance(bom=new_bom, output_format=OutputFormat.XML)
    outputterXML.output_to_file(filename=(args.output_file + ".onexml"), allow_overwrite=True)

    # Produce the output in XML format that is indented format.
    myxmldoc = minidom.parseString(open((args.output_file + ".onexml")).read())
    outputfile = open(args.output_file + ".xml", mode='w')
    print(myxmldoc.toprettyxml(), file=outputfile)
    outputfile.close()


# main()


if __name__ == "__main__":

    my_main()
