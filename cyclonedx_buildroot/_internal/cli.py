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

from __future__ import annotations
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
from cyclonedx.exception.factory import (
    InvalidLicenseExpressionException,
    InvalidSpdxLicenseException,
)
from cyclonedx.schema import SchemaVersion, OutputFormat
from cyclonedx.output import make_outputter
from cyclonedx.model.contact import OrganizationalEntity, OrganizationalContact
import configparser

if TYPE_CHECKING:
    from cyclonedx.output.xml import Xml as XmlOutputter

def read_config_file(path: str) -> dict[str, str] :
    """ Read configuration data from a file.

     -i INPUT_FILE         comma separated value (csv) file of buildroot manifest data
     -o OUTPUT_FILE        SBOM output file name for JSON and XML
     -n PRODUCT_NAME       name of the product
     -v PRODUCT_VERSION    product version string
     -m MANUFACTURER_NAME  name of product manufacturer
     -s SUPPLIER_NAME      name of SBOM Supplier
     -a AUTHOR_NAME        name of SBOM Author
     -c CPE_INPUT_FILE     cpe file from make show-info
     -f CONFIG_FILE        configuration file containing the above data

        :return: a list of configuration data
        :rtype: list()
   """

    configFileExists = os.path.isfile(path)

    if not configFileExists:
        print('Creating config.ini with default content, please edit the file to add values.')
        f = open(path, "w")
        f.write("[CycloneDX_Buildroot]\n")
        f.write("INPUT_FILE = <replace with name of input file>\n")
        f.write("OUTPUT_FILE = <replace with name of output file>\n")
        f.write("PRODUCT_NAME = <replace with name of product>\n")
        f.write("PRODUCT_VERSION = <replace with product version>\n")
        f.write("MANUFACTURER_NAME = <replace with name of product manufacturer>\n")
        f.write("SUPPLIER_NAME = <replace with name of product supplier>\n")
        f.write("AUTHOR_NAME = <replace with name of product author>\n")
        f.write("CPE_INPUT_FILE = <replace with name of CPE file>\n")
        f.close()
        config_values = {}
        exit(0)
    else:
        print('Found existing config file')

        # Get config.ini data to populate a ConfigParser object
        config = configparser.ConfigParser()
        config.read(path)

        # Access values from the configuration file
        input_file        = config.get('CycloneDX_Buildroot', 'input_file')
        output_file       = config.get('CycloneDX_Buildroot', 'output_file')
        product_name      = config.get('CycloneDX_Buildroot', 'product_name')
        product_version   = config.get('CycloneDX_Buildroot', 'product_version')
        manufacturer_name = config.get('CycloneDX_Buildroot', 'manufacturer_name')
        supplier_name     = config.get('CycloneDX_Buildroot', 'supplier_name')
        author_name       = config.get('CycloneDX_Buildroot', 'author_name')
        cpe_input_file    = config.get('CycloneDX_Buildroot', 'cpe_input_file')

        # Return a dictionary with the retrieved values
        config_values = {
            'input_file': input_file,
            'output_file': output_file,
            'product_name': product_name,
            'product_version': product_version,
            'manufacturer_name': manufacturer_name,
            'supplier_name': supplier_name,
            'author_name': author_name,
            'cpe_input_file': cpe_input_file,
        }

    return config_values

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


def _resolve_license_fragment(lfac: LicenseFactory, fragment: str) -> Any:
    try:
        return lfac.make_with_id(fragment)
    except InvalidSpdxLicenseException:
        return lfac.make_with_name(fragment)


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

                try:
                    license_for_component = [lfac.make_with_expression(license_string)]
                except InvalidLicenseExpressionException:
                    license_list = _split_non_parenthesized(license_string, ",")
                    license_for_component = [
                        _resolve_license_fragment(lfac, fragment.strip())
                        for fragment in license_list
                    ]

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
    try:
        with open(cpe_file_name) as cpe_file:
            cpe_data = json.load(cpe_file)
    except FileNotFoundError:
        print(f"DEBUG: cpe_file_name = {cpe_file_name!r}")
        print(f"DEBUG: os.getcwd() = {os.getcwd()}")
        print(f"DEBUG: file exists = {os.path.exists(cpe_file_name)}")
        print(f"DEBUG: os.path.abspath(input_file_name) = {os.path.abspath(cpe_file_name)}")
        raise  # re-raise so the test still fails

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
    parser.add_argument('-f', dest='config_file_name',  metavar="FILE", default=None,
                        help='Path to a configuration file name (optional)')
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

    parser.add_argument('-s', action='store', dest='supplier_name', default='unknown',
                        help='name of SBOM supplier')

    parser.add_argument('-a', action='store', dest='author_name', default='unknown',
                        help='name of SBOM author')

    args = parser.parse_args(argv)

    input_file = args.input_file
    output_file = args.output_file
    product_name = args.product_name
    product_version = args.product_version
    manufacturer_name = args.manufacturer_name
    cpe_input_file = args.cpe_input_file
    author_name = args.author_name
    supplier_name = args.supplier_name

    # default behavior expects user data supplied on the command line
    if args.config_file_name is None:
        print('Buildroot manifest input file: ' + input_file)
        print('Output SBOM: ' + output_file)
        print('SBOM Product Name: ' + product_name)
        print('SBOM Product Version: ' + product_version)
        print('SBOM Product Manufacturer: ' + manufacturer_name)
        print('Buildroot cpe input file: ' + cpe_input_file)
        print('SBOM author: ' + author_name)
        print('SBOM supplier: ' + supplier_name)
    else:
        # get data from the user specified configuration file
        config_data = read_config_file(args.config_file_name)

        input_file = config_data['input_file']
        output_file = config_data['output_file']
        product_name= config_data['product_name']
        product_version= config_data['product_version']
        manufacturer_name= config_data['manufacturer_name']
        supplier_name= config_data['supplier_name']
        author_name= config_data['author_name']
        cpe_input_file= config_data['cpe_input_file']

        # Support for proper pytest file path
        config_dir = os.path.dirname(os.path.abspath(args.config_file_name))
        if not os.path.isabs(input_file):
            input_file = os.path.join(config_dir, input_file)
            cpe_input_file = os.path.join(config_dir, cpe_input_file)

    br_bom = Bom()
    br_bom.metadata = BomMetaData(
        manufacturer=OrganizationalEntity(name=manufacturer_name),
        component=Component(name=product_name, version=product_version),
        supplier=OrganizationalEntity(name=supplier_name),
        authors=[OrganizationalContact(name=author_name)]
    )

    br_bom = create_buildroot_sbom(str(input_file).strip(" "), str(cpe_input_file).strip(" "), br_bom)

    # Produce the output in pretty JSON format.
    bom_json = BY_SCHEMA_VERSION[SchemaVersion.V1_6](br_bom).output_as_string(indent=3)
    with open((output_file + ".json"), mode='w') as outputfile:
        print(bom_json, file=outputfile)

    # Produce the output in XML format that is in a one-line format.
    my_xml_outputter: 'XmlOutputter' = make_outputter(br_bom, OutputFormat.XML, SchemaVersion.V1_6)
    serialized_xml = my_xml_outputter.output_as_string(indent=2)

    # Produce the output in XML format that is indented format.
    with open(output_file + ".xml", mode='w') as outputfile:
        print(serialized_xml, file=outputfile)

    return 0
