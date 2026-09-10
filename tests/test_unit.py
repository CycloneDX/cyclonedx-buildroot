# This file is part of CycloneDX-Buildroot
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
# Copyright (c) OWASP Foundation. All Rights Reserved.


import unittest

from cyclonedx.exception.factory import InvalidLicenseExpressionException
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression

from cyclonedx_buildroot._internal.cli import _split_non_parenthesized, _resolve_license_fragment


class TestUtils(unittest.TestCase):

    def test_split_non_parenthesized(self):
        result = _split_non_parenthesized("aaa,bbb(ccc,ddd),eee", ",")
        self.assertListEqual(result, ['aaa', 'bbb(ccc,ddd)', 'eee'])


class TestLicenseResolution(unittest.TestCase):

    def _resolve(self, license_string):
        lfac = LicenseFactory()
        try:
            return [lfac.make_with_expression(license_string)]
        except InvalidLicenseExpressionException:
            fragments = _split_non_parenthesized(license_string, ",")
            return [_resolve_license_fragment(lfac, f.strip()) for f in fragments]

    def test_single_spdx_id(self):
        result = self._resolve("GPL-2.0")
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], LicenseExpression)
        self.assertEqual(str(result[0].value), "GPL-2.0")

    def test_single_spdx_expression(self):
        result = self._resolve("GPL-2.0 or BSD-3-Clause")
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], LicenseExpression)

    def test_comma_separated_licenses_are_not_dropped(self):
        result = self._resolve("GPL-2.0, bzip2-1.0.4")
        self.assertEqual(len(result), 2)
        ids_or_names = [str(lic.id) if lic.id else str(lic.name) for lic in result]
        self.assertListEqual(ids_or_names, ["GPL-2.0", "bzip2-1.0.4"])

    def test_comma_separated_licenses_with_parenthesized_qualifiers(self):
        result = self._resolve(
            "LGPL-2.1+, GPL-2.0+ (udev), Public Domain (few source files, "
            "see README), BSD-3-Clause (tools/chromiumos)"
        )
        self.assertEqual(len(result), 4)

    def test_unrecognized_license_falls_back_to_name(self):
        result = self._resolve("Python-2.0, others")
        self.assertEqual(len(result), 2)
        self.assertEqual(str(result[1].name), "others")

    def test_fragment_that_is_itself_an_expression_does_not_mix_types(self):
        result = self._resolve("BSD-3-Clause or GPL-2.0, GPL-2.0+")
        self.assertEqual(len(result), 2)
        for license_ in result:
            self.assertIsInstance(license_, DisjunctiveLicense)
