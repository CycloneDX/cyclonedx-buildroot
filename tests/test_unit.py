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

from cyclonedx_buildroot._internal.cli import _split_non_parenthesized


class TestUtils(unittest.TestCase):

    def test_split_non_parenthesized(self):
        result = _split_non_parenthesized("aaa,bbb(ccc,ddd),eee", ",")
        self.assertListEqual(result, ['aaa', 'bbb(ccc,ddd)', 'eee'])
