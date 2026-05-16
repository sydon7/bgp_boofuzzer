import contextlib
import importlib
import sys
import types
import unittest
from unittest.mock import patch


from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.bgp_update import BaseUpdateFuzzer

from boofuzz import Block

import yaml

fuzz_utils = importlib.import_module("utils.fuzz_utils")



class TestBGPFuzzUtils(unittest.TestCase):


    def load_config_matrix(self, cfg_file="bgp_defaults.yaml"):
        """ load a config file for testing"""
        self.config_matrix = yaml.safe_load(open(cfg_file))



    def test_config_matrix(self):
    
        self.load_config_matrix()
        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=self.config_matrix, fuzz_matrix=None)
        s_initialize('CONFIG_MATRIX1')
        with s_block("Origin"):
            helper._one_byte_fuzz("Origin Flags", random_options=False)


        request = s_get("CONFIG_MATRIX1")

        field = request.names["CONFIG_MATRIX1.Origin.Origin Flags"]



        print("fuzzable:", field.fuzzable)
        print("name:", field.name)
        print("value:", field._default_value.hex())
        print("rendered:", request.render().hex())
        self.assertEqual(request.render(), b"\x40")


    def test_s_simple_byte(self):
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=None)
        s_initialize('BGP_OPEN')
        with s_block("Test Block"):
            helper.s_simple_byte(name="test", value=0x11, fuzzable=True)


        rendered = s_get("BGP_OPEN").render()
        #print(f"**{rendered}")
        self.assertEqual(rendered, b"\x11")

        

    def test_s_simple_byte_explicit_non_fuzzable(self):
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=None)
        s_initialize("BGP_OPEN_NON_FUZZABLE")
        with s_block("TestBlock"):
            helper.s_simple_byte(name="test", value=0x22, fuzzable=False)
  
        request = s_get("BGP_OPEN_NON_FUZZABLE")
        field = request.names["BGP_OPEN_NON_FUZZABLE.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value)
        #print("rendered:", request.render().hex())
        rendered = s_get("BGP_OPEN_NON_FUZZABLE").render()
  
        self.assertEqual(rendered, b"\x22")
        self.assertEqual(field.fuzzable, False)




    def test_s_simple_byte_explicit_fuzzable(self):

        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=None)
        s_initialize("BGP_OPEN_FUZZABLE")
        with s_block("TestBlock"):
            helper.s_simple_byte(name="test", value=0x11, fuzzable=True)
 


        request = s_get("BGP_OPEN_FUZZABLE")
        field = request.names["BGP_OPEN_FUZZABLE.TestBlock.test"]

        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value)
        #print("rendered:", request.render().hex())
        self.assertEqual(request.render(), b"\x11")
        self.assertEqual(field.fuzzable, True)
        #self.assertTrue(request.names["BGP_OPEN_FUZZABLE.TestBlock.test"].fuzzable)


    def test_one_byte_fuzz_with_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "33"
            }
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=None)
        s_initialize("BGP_OPEN_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._one_byte_fuzz(name="test", random_options=False)

        rendered = s_get("BGP_OPEN_CONFIG_MATRIX").render()
        #print(f"**{rendered}")
        ## testing that the default value from the config matrix is used
        #@ ie test should be 0x33 as per the config matrix, not 0x10 which is the default in the code
        self.assertEqual(rendered, b"\x33")

        ## now test a non matching name, which should default to the code default of 0x10
        s_initialize("BGP_OPEN_CONFIG_MATRIX_NO_MATCH")
        with s_block("TestBlock"):
            helper._one_byte_fuzz(name="non_matching_name", random_options=False)
        rendered_no_match = s_get("BGP_OPEN_CONFIG_MATRIX_NO_MATCH").render()
        #print(f"**{rendered_no_match}")
        self.assertEqual(rendered_no_match, b"\x10")


    def test_one_byte_fuzz_with_fuzz_matrix(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FUZZ_MATRIX")
        with s_block("TestBlock"):
            helper._one_byte_fuzz(name="test", random_options=True)

        field = s_get("BGP_OPEN_FUZZ_MATRIX").names["BGP_OPEN_FUZZ_MATRIX.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value)
        #print("rendered:", s_get("BGP_OPEN_FUZZ_MATRIX").render().hex())
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(s_get("BGP_OPEN_FUZZ_MATRIX").render(), b"\x10")


    def test_one_byte_fuzz_with_fuzz_matrix_non_fuzzable(self):
        fuzz_matrix = {
            "test": False
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FUZZ_MATRIX_NON_FUZZABLE")
        with s_block("TestBlock"):
            helper._one_byte_fuzz(name="test", random_options=True)

        field = s_get("BGP_OPEN_FUZZ_MATRIX_NON_FUZZABLE").names["BGP_OPEN_FUZZ_MATRIX_NON_FUZZABLE.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value)
        #print("rendered:", s_get("BGP_OPEN_FUZZ_MATRIX_NON_FUZZABLE").render().hex())
        self.assertEqual(field.fuzzable, False)
        self.assertEqual(s_get("BGP_OPEN_FUZZ_MATRIX_NON_FUZZABLE").render(), b"\x10")


    def test_one_byte_fuzz_with_fuzz_matrix_random_options(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FUZZ_MATRIX_RANDOM_OPTIONS")
        with s_block("TestBlock"):
            helper._one_byte_fuzz(name="test", random_options=True)

        field = s_get("BGP_OPEN_FUZZ_MATRIX_RANDOM_OPTIONS").names["BGP_OPEN_FUZZ_MATRIX_RANDOM_OPTIONS.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value)
        #print("rendered:", s_get("BGP_OPEN_FUZZ_MATRIX_RANDOM_OPTIONS").render().hex())
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(s_get("BGP_OPEN_FUZZ_MATRIX_RANDOM_OPTIONS").render(), b"\x10")


    def test_one_byte_fuzz_with_fuzz_matrix_and_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "44"
            }
        }
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FUZZ_AND_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._one_byte_fuzz(name="test", random_options=True)

        field = s_get("BGP_OPEN_FUZZ_AND_CONFIG_MATRIX").names["BGP_OPEN_FUZZ_AND_CONFIG_MATRIX.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value)
        #print("rendered:", s_get("BGP_OPEN_FUZZ_AND_CONFIG_MATRIX").render().hex())
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(s_get("BGP_OPEN_FUZZ_AND_CONFIG_MATRIX").render(), b"\x44")


    def test_two_byte_fuzz_with_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "33 44"
            }
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=None)
        s_initialize("BGP_OPEN_TWO_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._two_byte_fuzz(name="test", random_options=False)


        request = s_get("BGP_OPEN_TWO_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_TWO_CONFIG_MATRIX.TestBlock.test"]
        rendered = request.render()

        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", rendered.hex())

        self.assertEqual(rendered, b"\x33\x44")

        s_initialize("BGP_OPEN_TWO_CONFIG_MATRIX_NO_MATCH")
        with s_block("TestBlock"):
            helper._two_byte_fuzz(name="non_matching_name", random_options=False)
        request_no_match = s_get("BGP_OPEN_TWO_CONFIG_MATRIX_NO_MATCH")
        rendered_no_match = request_no_match.render()
        self.assertEqual(rendered_no_match, b"\x10\x10")

    def test_two_byte_fuzz_with_fuzz_matrix(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_TWO_FUZZ_MATRIX")
        with s_block("TestBlock"):
            helper._two_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_TWO_FUZZ_MATRIX")
        field = request.names["BGP_OPEN_TWO_FUZZ_MATRIX.TestBlock.test"]
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10")
        rendered = request.render()
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", rendered.hex())
        self.assertEqual(rendered, b"\x10\x10")


    def test_two_byte_fuzz_with_fuzz_matrix_non_fuzzable(self):
        fuzz_matrix = {
            "test": False
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_TWO_FUZZ_MATRIX_NON_FUZZABLE")
        with s_block("TestBlock"):
            helper._two_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_TWO_FUZZ_MATRIX_NON_FUZZABLE")
        field = request.names["BGP_OPEN_TWO_FUZZ_MATRIX_NON_FUZZABLE.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())
        self.assertEqual(field.fuzzable, False)
        self.assertEqual(request.render(), b"\x10\x10")

    def test_two_byte_fuzz_with_fuzz_matrix_random_options(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_TWO_FUZZ_MATRIX_RANDOM_OPTIONS")
        with s_block("TestBlock"):
            helper._two_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_TWO_FUZZ_MATRIX_RANDOM_OPTIONS")
        field = request.names["BGP_OPEN_TWO_FUZZ_MATRIX_RANDOM_OPTIONS.TestBlock.test"]

        #print("#fuzzable:", field.fuzzable)
        #print("#name:", field.name)
        #print("#value:", field._default_value.hex())
        #print("#rendered:", request.render().hex())

        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10")
        self.assertEqual(request.render(), b"\x10\x10")

    def test_two_byte_fuzz_with_fuzz_matrix_and_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "44 55"
            }
        }
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_TWO_FUZZ_AND_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._two_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_TWO_FUZZ_AND_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_TWO_FUZZ_AND_CONFIG_MATRIX.TestBlock.test"]

        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())

        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x44\x55")
        self.assertEqual(request.render(), b"\x44\x55")

    def test_three_byte_fuzz_with_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "33 44 55"
            }
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=None)
        s_initialize("BGP_OPEN_THREE_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._three_byte_fuzz(name="test", random_options=False)

        request = s_get("BGP_OPEN_THREE_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_THREE_CONFIG_MATRIX.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())

        rendered = request.render()

        self.assertEqual(rendered, b"\x33\x44\x55")

        s_initialize("BGP_OPEN_THREE_CONFIG_MATRIX_NO_MATCH")
        with s_block("TestBlock"):
            helper._three_byte_fuzz(name="non_matching_name", random_options=False)
        request_no_match = s_get("BGP_OPEN_THREE_CONFIG_MATRIX_NO_MATCH")

        field_no_match = request_no_match.names["BGP_OPEN_THREE_CONFIG_MATRIX_NO_MATCH.TestBlock.non_matching_name"]
        #print("fuzzable:", field_no_match.fuzzable)
        #print("name:", field_no_match.name)
        #print("value:", field_no_match._default_value.hex())
        #print("rendered:", request_no_match.render().hex())

        rendered_no_match = request_no_match.render()
        self.assertEqual(rendered_no_match, b"\x10\x10\x10")

    def test_three_byte_fuzz_with_fuzz_matrix(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_THREE_FUZZ_MATRIX")
        with s_block("TestBlock"):
            helper._three_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_THREE_FUZZ_MATRIX")
        field = request.names["BGP_OPEN_THREE_FUZZ_MATRIX.TestBlock.test"]

        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())


        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10\x10")
        rendered = request.render()
        self.assertEqual(rendered, b"\x10\x10\x10")

    def test_three_byte_fuzz_with_fuzz_matrix_non_fuzzable(self):
        fuzz_matrix = {
            "test": False
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_THREE_FUZZ_MATRIX_NON_FUZZABLE")
        with s_block("TestBlock"):
            helper._three_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_THREE_FUZZ_MATRIX_NON_FUZZABLE")
        field = request.names["BGP_OPEN_THREE_FUZZ_MATRIX_NON_FUZZABLE.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())

        self.assertEqual(field.fuzzable, False)
        self.assertEqual(request.render(), b"\x10\x10\x10")

    def test_three_byte_fuzz_with_fuzz_matrix_random_options(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_THREE_FUZZ_MATRIX_RANDOM_OPTIONS")
        with s_block("TestBlock"):
            helper._three_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_THREE_FUZZ_MATRIX_RANDOM_OPTIONS")
        field = request.names["BGP_OPEN_THREE_FUZZ_MATRIX_RANDOM_OPTIONS.TestBlock.test"]

        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())

        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10\x10")
        self.assertEqual(request.render(), b"\x10\x10\x10")

    def test_three_byte_fuzz_with_fuzz_matrix_and_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "44 55 66"
            }
        }
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_THREE_FUZZ_AND_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._three_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_THREE_FUZZ_AND_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_THREE_FUZZ_AND_CONFIG_MATRIX.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())

        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x44\x55\x66")
        self.assertEqual(request.render(), b"\x44\x55\x66")

    def test_four_byte_fuzz_with_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "33 44 55 66"
            }
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=None)
        s_initialize("BGP_OPEN_FOUR_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._four_byte_fuzz(name="test", random_options=False)

        request = s_get("BGP_OPEN_FOUR_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_FOUR_CONFIG_MATRIX.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())
        rendered = request.render()

        self.assertEqual(rendered, b"\x33\x44\x55\x66")

        s_initialize("BGP_OPEN_FOUR_CONFIG_MATRIX_NO_MATCH")
        with s_block("TestBlock"):
            helper._four_byte_fuzz(name="non_matching_name", random_options=False)
        request_no_match = s_get("BGP_OPEN_FOUR_CONFIG_MATRIX_NO_MATCH")
        rendered_no_match = request_no_match.render()
        self.assertEqual(rendered_no_match, b"\x10\x10\x10\x10")

    def test_four_byte_fuzz_with_fuzz_matrix(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FOUR_FUZZ_MATRIX")
        with s_block("TestBlock"):
            helper._four_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_FOUR_FUZZ_MATRIX")
        field = request.names["BGP_OPEN_FOUR_FUZZ_MATRIX.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())

        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10\x10\x10")
        rendered = request.render()
        self.assertEqual(rendered, b"\x10\x10\x10\x10")

    def test_four_byte_fuzz_with_fuzz_matrix_non_fuzzable(self):
        fuzz_matrix = {
            "test": False
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FOUR_FUZZ_MATRIX_NON_FUZZABLE")
        with s_block("TestBlock"):
            helper._four_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_FOUR_FUZZ_MATRIX_NON_FUZZABLE")
        field = request.names["BGP_OPEN_FOUR_FUZZ_MATRIX_NON_FUZZABLE.TestBlock.test"]
        self.assertEqual(field.fuzzable, False)
        self.assertEqual(request.render(), b"\x10\x10\x10\x10")

    def test_four_byte_fuzz_with_fuzz_matrix_random_options(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FOUR_FUZZ_MATRIX_RANDOM_OPTIONS")
        with s_block("TestBlock"):
            helper._four_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_FOUR_FUZZ_MATRIX_RANDOM_OPTIONS")
        field = request.names["BGP_OPEN_FOUR_FUZZ_MATRIX_RANDOM_OPTIONS.TestBlock.test"]
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10\x10\x10")
        self.assertEqual(request.render(), b"\x10\x10\x10\x10")

    def test_four_byte_fuzz_with_fuzz_matrix_and_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "44 55 66 77"
            }
        }
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_FOUR_FUZZ_AND_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._four_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_FOUR_FUZZ_AND_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_FOUR_FUZZ_AND_CONFIG_MATRIX.TestBlock.test"]
        #print("fuzzable:", field.fuzzable)
        #print("name:", field.name)
        #print("value:", field._default_value.hex())
        #print("rendered:", request.render().hex())
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x44\x55\x66\x77")
        self.assertEqual(request.render(), b"\x44\x55\x66\x77")

    def test_eight_byte_fuzz_with_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "33 44 55 66 77 88 99 AA"
            }
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=None)
        s_initialize("BGP_OPEN_EIGHT_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._eight_byte_fuzz(name="test", random_options=False)

        request = s_get("BGP_OPEN_EIGHT_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_EIGHT_CONFIG_MATRIX.TestBlock.test"]
        rendered = request.render()

        self.assertEqual(rendered, b"\x33\x44\x55\x66\x77\x88\x99\xAA")

        s_initialize("BGP_OPEN_EIGHT_CONFIG_MATRIX_NO_MATCH")
        with s_block("TestBlock"):
            helper._eight_byte_fuzz(name="non_matching_name", random_options=False)
        request_no_match = s_get("BGP_OPEN_EIGHT_CONFIG_MATRIX_NO_MATCH")
        rendered_no_match = request_no_match.render()
        self.assertEqual(rendered_no_match, b"\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_eight_byte_fuzz_with_fuzz_matrix(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_EIGHT_FUZZ_MATRIX")
        with s_block("TestBlock"):
            helper._eight_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_EIGHT_FUZZ_MATRIX")
        field = request.names["BGP_OPEN_EIGHT_FUZZ_MATRIX.TestBlock.test"]
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10\x10\x10\x10\x10\x10\x10")
        rendered = request.render()
        self.assertEqual(rendered, b"\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_eight_byte_fuzz_with_fuzz_matrix_non_fuzzable(self):
        fuzz_matrix = {
            "test": False
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_EIGHT_FUZZ_MATRIX_NON_FUZZABLE")
        with s_block("TestBlock"):
            helper._eight_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_EIGHT_FUZZ_MATRIX_NON_FUZZABLE")
        field = request.names["BGP_OPEN_EIGHT_FUZZ_MATRIX_NON_FUZZABLE.TestBlock.test"]
        self.assertEqual(field.fuzzable, False)
        self.assertEqual(request.render(), b"\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_eight_byte_fuzz_with_fuzz_matrix_random_options(self):
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_EIGHT_FUZZ_MATRIX_RANDOM_OPTIONS")
        with s_block("TestBlock"):
            helper._eight_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_EIGHT_FUZZ_MATRIX_RANDOM_OPTIONS")
        field = request.names["BGP_OPEN_EIGHT_FUZZ_MATRIX_RANDOM_OPTIONS.TestBlock.test"]
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x10\x10\x10\x10\x10\x10\x10\x10")
        self.assertEqual(request.render(), b"\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_eight_byte_fuzz_with_fuzz_matrix_and_config_matrix(self):
        config_matrix = {
            "default_values": {
                "test": "44 55 66 77 88 99 AA BB"
            }
        }
        fuzz_matrix = {
            "test": True
        }
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix=config_matrix, fuzz_matrix=fuzz_matrix)
        s_initialize("BGP_OPEN_EIGHT_FUZZ_AND_CONFIG_MATRIX")
        with s_block("TestBlock"):
            helper._eight_byte_fuzz(name="test", random_options=True)

        request = s_get("BGP_OPEN_EIGHT_FUZZ_AND_CONFIG_MATRIX")
        field = request.names["BGP_OPEN_EIGHT_FUZZ_AND_CONFIG_MATRIX.TestBlock.test"]
        self.assertEqual(field.fuzzable, True)
        self.assertEqual(field._default_value, b"\x44\x55\x66\x77\x88\x99\xAA\xBB")
        self.assertEqual(request.render(), b"\x44\x55\x66\x77\x88\x99\xAA\xBB")


    def test_flowspec_port_one_or_two_byte(self):
        fuzz_utils = importlib.import_module("utils.fuzz_utils")

        helper = fuzz_utils.bgp_fuzz_utils_class(config_matrix={}, fuzz_matrix=None)
        s_initialize("BGP_FLOW_SPEC_PORT")
        mode = 1
        with s_block("TestBlock"):
            mode = helper._flowspec_port_one_or_two_byte(name="port_test", random_options=False)

        request = s_get("BGP_FLOW_SPEC_PORT")
        field = request.names["BGP_FLOW_SPEC_PORT.TestBlock.port_test"]
        rendered = request.render()

        print("fuzzable:", field.fuzzable)
        print("name:", field.name)
        print("rendered:", rendered.hex())

        if mode == 1:
             self.assertEqual(rendered, b"\x81")
        else:
            self.assertEqual(rendered, b"\x91\x91")



if __name__ == "__main__":
	unittest.main()
