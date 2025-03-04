from os import chdir, getcwd
from os.path import join
from  tempfile import TemporaryDirectory
import unittest
from shutil import copy

from . import run_cli, DATA_DIR, TMP_DIR


class TestRunCli(unittest.TestCase):

    def setUp(self):
        self.__original_cwd = getcwd()
        self.__tempdir = TemporaryDirectory(prefix=f'{self.__class__.__name__}.', dir=TMP_DIR)
        chdir(self.__tempdir.name)

    def tearDown(self):
        chdir(self.__original_cwd)
        # self.__tempdir.cleanup()

    def test_all_default_values(self):
        copy(join(DATA_DIR, "manifest.csv"), join(self.__tempdir.name, "manifest.csv"))
        res, out, err = run_cli()
        self.assertEqual(0, res, '\n'.join((out, err)))

    def test_valid_input_file_only(self):
        res, out, err = run_cli("-i", join(DATA_DIR, "manifest.csv"))
        self.assertEqual(0, res, '\n'.join((out, err)))

    def test_valid_output_file_only(self):
        copy(join(DATA_DIR, "manifest.csv"), join(self.__tempdir.name, "manifest.csv"))
        res, out, err = run_cli("-o", "unittest_output.txt")
        self.assertEqual(0, res, '\n'.join((out, err)))

    def test_valid_product_name_only(self):
        copy(join(DATA_DIR, "manifest.csv"), join(self.__tempdir.name, "manifest.csv"))
        res, out, err = run_cli("-n", "unittest_product_name")
        self.assertEqual(0, res, '\n'.join((out, err)))

    def test_valid_version_only(self):
        copy(join(DATA_DIR, "manifest.csv"), join(self.__tempdir.name, "manifest.csv"))
        res, out, err = run_cli("-v", "unittest_product_version")
        self.assertEqual(0, res, '\n'.join((out, err)))

    def test_valid_manufacturer_name_only(self):
        copy(join(DATA_DIR, "manifest.csv"), join(self.__tempdir.name, "manifest.csv"))
        res, out, err = run_cli("-m", "unittest_manufacturer_name")
        self.assertEqual(0, res, '\n'.join((out, err)))

    # Test against the output of make show-info

    def test_valid_cpe_input_file(self):
        copy(join(DATA_DIR, "manifest.csv"), join(self.__tempdir.name, "manifest.csv"))
        res, out, err = run_cli("-c", join(DATA_DIR, "cpe_data_pp.json"))
        self.assertEqual(0, res, '\n'.join((out, err)))

    # Test against the output of make pkg-stats

    def test_valid_cpe_input_file2(self):
        copy(join(DATA_DIR, "manifest.csv"), join(self.__tempdir.name, "manifest.csv"))
        res, out, err = run_cli("-c", join(DATA_DIR, "cpe_data_show_pkg_stats.json"))
        self.assertEqual(0, res, '\n'.join((out, err)))
