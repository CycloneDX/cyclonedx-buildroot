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


from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO, TextIOWrapper
from typing import Any, Optional
from unittest.mock import patch
from os.path import dirname, join
from tempfile import TemporaryDirectory

from cyclonedx_buildroot._internal.cli import run as _run_cli

def run_cli(*args: str, inp: Optional[Any] = None) -> (int, str, str):
    with StringIO() as err, StringIO() as out:
        err.name = '<fakeerr>'
        out.name = '<fakeout>'
        with redirect_stderr(err), redirect_stdout(out):
            with patch('sys.stdin', TextIOWrapper(inp or BytesIO())):
                try:
                    c_res = _run_cli(argv=args)
                except SystemExit as e:
                    c_res = e.code
            c_out = out.getvalue()
            c_err = err.getvalue()
        return c_res, c_out, c_err


DATA_DIR = join(dirname(__file__), '_data')

TMP_DIR = join(dirname(__file__), '_tmp')
