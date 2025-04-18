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
import os
from typing import Optional, Sequence, Any, Union, NoReturn, List, TYPE_CHECKING

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.output.json import BY_SCHEMA_VERSION
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from cyclonedx.factory.license import LicenseFactory
from defusedxml.minidom import parseString as minidom_parseString  # type: ignore
from cyclonedx.exception.factory import InvalidLicenseExpressionException
from cyclonedx.schema import SchemaVersion, OutputFormat
from cyclonedx.output import make_outputter
from cyclonedx.model.contact import OrganizationalEntity


if TYPE_CHECKING:
    from cyclonedx.output.xml import Xml as XmlOutputter

# Splits a string by the given separator character except inside parentheses.
def _split_non_parenthesized(text: str, separator: str) -> List[str]:
    fragments = []
    current_fragment = ''
    parentheses_count = 0
    for c in text:
        if c == separator and parentheses_count == 0:
            fragments.append(current_fragment)
            current_fragment = ''
        else:
            current_fragment += c
            if c == ')' and parentheses_count > 0: parentheses_count -= 1
            if c == '(': parentheses_count += 1

    fragments.append(current_fragment)
    return fragments


# Buildroot manifest.csv file header shows the following header row
# PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES
#
# noinspection PyTypeChecker
def create_buildroot_sbom(input_file_name: str, cpe_file_name: str, br_bom: Bom) -> Bom:
    br_bom_local = br_bom
    root_component = br_bom.metadata.component
    assert root_component is not None

    #
    # Capture the components that describe the complete inventory of first-party software
    # Buildroot CSV file supplies software package data in each row. Any change to that map of data will break
    # the resulting JSON. Use a try/except block to help with run time issues.
    with open(input_file_name, newline='') as csvfile:
        spread_sheet = csv.DictReader(csvfile)

        for row in spread_sheet:
            try:
                download_url_with_slash = row['SOURCE SITE'] + "/" + row['SOURCE ARCHIVE']
                purl_info = PackageURL(type='generic', name=row['PACKAGE'], version=row['VERSION'],
                                       qualifiers={'download_url': download_url_with_slash})

                lfac = LicenseFactory()
                license_string = row['LICENSE']
                # TODO license_list not used something is wrong.
                license_list = _split_non_parenthesized(license_string, ",")

                try:
                    license_for_component = [lfac.make_with_expression(license_string)]
                except InvalidLicenseExpressionException:
                    license_for_component = []

                cpe_id_value: Optional[str] = get_cpe_value(cpe_file_name, row['PACKAGE'])
                if cpe_id_value == "":
                    cpe_id_value = None
                next_component = Component(name=row['PACKAGE'],
                                           type=ComponentType.FIRMWARE,
                                           licenses=license_for_component,
                                           version=row['VERSION'],
                                           purl=purl_info,
                                           cpe=cpe_id_value,
                                           bom_ref=row['PACKAGE'])

                br_bom_local.components.add(next_component)
                br_bom_local.register_dependency(root_component, [next_component])
            except KeyError:
                print("The input file header does not contain the expected data in the first row of the file.")
                print(
                    "Expected PACKAGE,VERSION,LICENSE,LICENSE FILES,SOURCE ARCHIVE,SOURCE SITE,DEPENDENCIES WITH LICENSES")
                print("Found the following in the csv file first row:", row)
                print("Cannot continue with the provided input file. Exiting.")
                exit(-1)

    return br_bom_local


# From the cpe.json file iterate across the list of components
# For each component in the br_bom search the cpe file for a matching component by comparing
# either bom-ref or name field. Once a match is found from the cpe file copy the name value
# pair of the cpe-id field replacing the purl field in br_bom.
# Supports the Buildroot target "make show-info" or "make pkg-stats"
#
# input : name of the software component
# output: returns the cpe value
def get_cpe_value(cpe_file_name: str, sw_component_name: str) -> str:
    retval = ""
    if cpe_file_name == "unknown":
        return retval
    with open(cpe_file_name) as cpe_file:
        cpe_data = json.load(cpe_file)
    assert isinstance(cpe_data, dict)
    for cpe_key, cpe_value in cpe_data.items():
        try:
            # noinspection PyTypeChecker
            sw_object = cpe_data[cpe_key]
            if isinstance(sw_object, dict) and sw_object['name'] == sw_component_name:
                retval = sw_object['cpe-id']
                return retval
        except KeyError:
            # Some entries do not have a "name" key and no "cpe-id" so skip these.
            pass
        try:
            # "make pkg-stats"
            if sw_component_name in cpe_value:
                sw_object = cpe_value[sw_component_name]
                retval = sw_object['cpeid']
                return retval
        except KeyError:
            # Some entries do not have a "name" key and no "cpe-id" so skip these.
            pass
    return retval


def run(*, argv: Optional[Sequence[str]] = None, **kwargs: Any) -> Union[int, NoReturn]:

    parser = argparse.ArgumentParser(description='CycloneDX BOM Generator', **kwargs)
    parser.add_argument('-i', action='store', dest='input_file', default='manifest.csv',
                        help='comma separated value (csv) file of buildroot manifest data')
    parser.add_argument('-o', action='store', dest='output_file', default='buildroot_IOT_sbom',
                        help='SBOM output file name for json and xml')
    parser.add_argument('-n', action='store', dest='product_name', default='unknown', help='name of the product')
    parser.add_argument('-v', action='store', dest='product_version', default='unknown', help='product version string')
    parser.add_argument('-m', action='store', dest='manufacturer_name', default='unknown',
                        help='name of product manufacturer')
    parser.add_argument('-c', action='store', dest='cpe_input_file', default='unknown',
                        help='cpe file from make show-info')

    args = parser.parse_args(argv)

    print('Buildroot manifest input file: ' + args.input_file)
    print('Output SBOM: ' + args.output_file)
    print('SBOM Product Name: ' + args.product_name)
    print('SBOM Product Version: ' + args.product_version)
    print('SBOM Product Manufacturer: ' + args.manufacturer_name)
    print('Buildroot cpe input file: ' + args.cpe_input_file)

    br_bom = Bom()
    br_bom.metadata = BomMetaData(
        manufacturer=OrganizationalEntity(name=args.manufacturer_name),
        component=Component(name=args.product_name, version=args.product_version)
    )

    br_bom = create_buildroot_sbom(str(args.input_file).strip(" "), str(args.cpe_input_file).strip(" "), br_bom)

    # Produce the output in pretty JSON format.
    bom_json = BY_SCHEMA_VERSION[SchemaVersion.V1_6](br_bom).output_as_string(indent=3)
    with open((args.output_file + ".json"), mode='w') as outputfile:
        json.dump(json.loads(bom_json), outputfile, indent=3)

    # Produce the output in XML format that is in a one-line format.
    my_xml_outputter: 'XmlOutputter' = make_outputter(br_bom, OutputFormat.XML, SchemaVersion.V1_6)
    my_xml_outputter.output_to_file(filename=(args.output_file + ".one.xml"), allow_overwrite=True)

    # Produce the output in XML format that is indented format.
    with open((args.output_file + ".one.xml")) as myxmldocfile:
        myxmldoc = minidom_parseString(myxmldocfile.read())
    with open(args.output_file + ".xml", mode='w') as outputfile:
        print(myxmldoc.toprettyxml(), file=outputfile)
    os.remove(args.output_file + ".one.xml")

    return 0
