import argparse
import sys
import unittest
import generateBuildrootSBOM

class TestStringMethods(unittest.TestCase):

    def test_all_default_values(self):
        generateBuildrootSBOM.my_main()
        assert 1

    def test_valid_input_file_only(self):
        generateBuildrootSBOM.my_main("-i man.csv")
        assert 1
    def test_valid_output_file_only(self):
        generateBuildrootSBOM.my_main("-o unittest_output.txt")
        assert 1

    def test_valid_product_name_only(self):
        generateBuildrootSBOM.my_main("-n unittest_product_name")
        assert 1
    def test_valid_version_only(self):
        generateBuildrootSBOM.my_main("-v unittest_product_version")
        assert 1

    def test_valid_manufacturer_name_only(self):
        generateBuildrootSBOM.my_main("-m unittest_manufacturer_name")
        assert 1

if __name__ == '__main__':
    unittest.main()
