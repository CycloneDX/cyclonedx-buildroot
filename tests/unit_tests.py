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

    # def test_invalid_input_file_only(self):
    #     generateBuildrootSBOM.my_main("-ijunk")
    #     with self.assertRaisesRegex(FileNotFoundError,"No such file"):
    #         assert 1

if __name__ == '__main__':
    unittest.main()

# if __name__ == '__main__':
#     parser = argparse.ArgumentParser()
#     #parser.add_argument('--input', default='My Input')
#     parser.add_argument('unittest_args', nargs='*')
#
#     args = parser.parse_args()
#
#     # Now set the sys.argv to the unittest_args (leaving sys.argv[0] alone)
#     sys.argv[1:] = args.unittest_args
#     print("unittest will see these args ", str(args.unittest_args))
#     unit_argv =  args.unittest_args
#     unittest.main(argv=unit_argv)